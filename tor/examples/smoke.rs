// Starts Tor and asks the given onion host for a path through the SOCKS port, then shows a host the port must refuse,
// then makes the same request with reqwest through socks5h, as the desktop app's HTTP plugin does.
//   cargo run --release --example smoke -- <state dir> <host.onion> <path>
use std::io::{Read, Write};

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let t = std::time::Instant::now();
    let port = kaspachat_tor::start(std::path::Path::new(&a[1]), vec![a[2].clone()]).await.expect("tor");
    println!("tor ready in {:.1} s, socks port {port}", t.elapsed().as_secs_f32());
    let (host, path) = (a[2].clone(), a[3].clone());
    tokio::task::spawn_blocking(move || {
        for h in [host.as_str(), "example.com"] {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(&[5, 1, 0]).unwrap();
            let mut b = [0u8; 2];
            s.read_exact(&mut b).unwrap();
            let mut req = vec![5, 1, 0, 3, h.len() as u8];
            req.extend(h.as_bytes());
            req.extend(80u16.to_be_bytes());
            s.write_all(&req).unwrap();
            let mut r = [0u8; 10];
            s.read_exact(&mut r).unwrap();
            if r[1] != 0 {
                println!("{h}: refused by the SOCKS port (code {})", r[1]);
                continue;
            }
            write!(s, "GET {path} HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n").unwrap();
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            println!("{h}: {}", out.lines().next().unwrap_or("no answer"));
        }
    })
    .await
    .unwrap();
    let c = reqwest::Client::builder().proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).unwrap()).build().unwrap();
    match c.get(format!("http://{}{}", a[2], a[3])).send().await {
        Ok(r) => println!("reqwest via socks5h: HTTP {}", r.status()),
        Err(e) => println!("reqwest via socks5h failed: {e}"),
    }
}
