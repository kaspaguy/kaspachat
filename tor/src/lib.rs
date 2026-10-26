// Tor for the native apps (PROTOCOL_SPEC §6.3). Embedded Arti and a SOCKS5 port on 127.0.0.1 that only connects to
// the given .onion hosts, so it can't be used as a general proxy by anything else on the device. The apps send every
// request to Kaspaguy's onion address through it: the relay and indexer never see the user's IP address.
use arti_client::{TorClient, TorClientConfig, config::TorClientConfigBuilder};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Tor = std::sync::Arc<TorClient<tor_rtcompat::PreferredRuntime>>;

/// Connects to the Tor network (state and cache under `dir`) and opens the SOCKS5 port. Returns the port once Tor is
/// ready; the proxy keeps running on the current Tokio runtime.
pub async fn start(dir: &Path, hosts: Vec<String>) -> Result<u16, String> {
    // Arti's TLS needs a process-wide crypto provider; an app that already chose one keeps it.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut b = TorClientConfigBuilder::from_directories(dir.join("state"), dir.join("cache"));
    // Android's and iOS's app directories sit under system-owned parents that Arti's permission check would refuse.
    if cfg!(any(target_os = "android", target_os = "ios")) {
        b.storage().permissions().dangerously_trust_everyone();
    }
    let cfg: TorClientConfig = b.build().map_err(|e| e.to_string())?;
    let tor: Tor = TorClient::create_bootstrapped(cfg).await.map_err(|e| e.to_string())?;
    let mut listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((s, _)) => {
                    let (tor, hosts) = (tor.clone(), hosts.clone());
                    tokio::spawn(async move {
                        let _ = socks(s, &tor, &hosts).await;
                    });
                }
                // iOS can reclaim a suspended app's sockets, leaving the listener dead: take the same port again (the
                // app keeps using the port it was given). A listener that is still fine keeps it, and the bind fails.
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    if let Ok(l) = TcpListener::bind(("127.0.0.1", port)).await {
                        listener = l;
                    }
                }
            }
        }
    });
    Ok(port)
}

// SOCKS5, no authentication, CONNECT to a domain name only (RFC 1928).
async fn socks(mut s: TcpStream, tor: &Tor, hosts: &[String]) -> std::io::Result<()> {
    let bad = || std::io::Error::other("socks");
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await?;
    let mut methods = vec![0u8; h[1] as usize];
    s.read_exact(&mut methods).await?;
    if h[0] != 5 || !methods.contains(&0) {
        s.write_all(&[5, 0xff]).await?;
        return Err(bad());
    }
    s.write_all(&[5, 0]).await?;
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await?;
    if r[0] != 5 || r[1] != 1 || r[3] != 3 {
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(bad());
    }
    let mut n = [0u8; 1];
    s.read_exact(&mut n).await?;
    let mut host = vec![0u8; n[0] as usize];
    s.read_exact(&mut host).await?;
    let port = s.read_u16().await?;
    let host = String::from_utf8(host).map_err(|_| bad())?;
    if !hosts.iter().any(|a| a.eq_ignore_ascii_case(&host)) {
        s.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await?; // not allowed by ruleset
        return Err(bad());
    }
    let mut t = match tor.connect((host.as_str(), port)).await {
        Ok(t) => t,
        Err(_) => {
            s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?; // host unreachable
            return Err(bad());
        }
    };
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut s, &mut t).await?;
    Ok(())
}

// Android: TorBridge.start(dir, hosts) blocks until Tor is ready and returns the SOCKS port, or a negative number with
// the reason in TorBridge.error(). Call it off the main thread.
#[cfg(target_os = "android")]
mod android {
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::{jint, jstring};
    use std::sync::{Mutex, OnceLock};

    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    static ERR: Mutex<String> = Mutex::new(String::new());

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_com_kaspaguy_kaspachat_TorBridge_start(mut env: JNIEnv, _: JClass, dir: JString, hosts: JString) -> jint {
        let dir: String = env.get_string(&dir).map(Into::into).unwrap_or_default();
        let hosts: String = env.get_string(&hosts).map(Into::into).unwrap_or_default();
        let rt = RT.get_or_init(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime"));
        match rt.block_on(super::start(std::path::Path::new(&dir), hosts.split(',').map(str::to_string).collect())) {
            Ok(p) => p as jint,
            Err(e) => {
                *ERR.lock().unwrap() = e;
                -1
            }
        }
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_com_kaspaguy_kaspachat_TorBridge_error(env: JNIEnv, _: JClass) -> jstring {
        env.new_string(ERR.lock().unwrap().as_str()).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
    }
}

// iOS (C, header in tor/include/kaspachat_tor.h): kc_tor_start(dir, hosts) blocks until Tor is ready and returns the SOCKS
// port, or -1 with the reason in kc_tor_error() (valid until the next failed start). Call it off the main thread.
// Built for tests too, so the C side is checked on Linux.
#[cfg(any(target_os = "ios", test))]
pub mod ffi {
    use std::ffi::{CStr, CString, c_char};
    use std::sync::{Mutex, OnceLock};

    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    static ERR: Mutex<Option<CString>> = Mutex::new(None);

    /// # Safety
    /// `dir` and `hosts` (comma-separated) must be valid NUL-terminated strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kc_tor_start(dir: *const c_char, hosts: *const c_char) -> i32 {
        let s = |p: *const c_char| if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() };
        let (dir, hosts) = (s(dir), s(hosts));
        let rt = RT.get_or_init(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime"));
        match rt.block_on(super::start(std::path::Path::new(&dir), hosts.split(',').map(str::to_string).collect())) {
            Ok(p) => p as i32,
            Err(e) => {
                *ERR.lock().unwrap() = Some(CString::new(e.replace('\0', " ")).unwrap());
                -1
            }
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn kc_tor_error() -> *const c_char {
        ERR.lock().unwrap().as_ref().map_or(c"".as_ptr(), |e| e.as_ptr())
    }
}

#[cfg(test)]
mod tests {
    use super::ffi::{kc_tor_error, kc_tor_start};
    use std::ffi::CStr;

    // A directory Arti can't create fails cleanly through the C interface, with the reason readable afterwards.
    #[test]
    fn c_start_reports_errors() {
        let p = unsafe { kc_tor_start(c"/proc/kaspachat-tor-test".as_ptr(), c"x.onion".as_ptr()) };
        assert_eq!(p, -1);
        let e = unsafe { CStr::from_ptr(kc_tor_error()) }.to_string_lossy().into_owned();
        assert!(!e.is_empty(), "error text");
    }

    // The real thing, through the C interface: needs the network, so run it by hand with --ignored.
    #[test]
    #[ignore]
    fn c_start_bootstraps() {
        let dir = std::env::temp_dir().join(format!("kc-tor-test-{}", std::process::id()));
        let d = std::ffi::CString::new(dir.to_str().unwrap()).unwrap();
        let p = unsafe { kc_tor_start(d.as_ptr(), c"x.onion".as_ptr()) };
        assert!(p > 0, "{}", unsafe { CStr::from_ptr(kc_tor_error()) }.to_string_lossy());
    }
}
