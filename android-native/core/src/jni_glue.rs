//! JNI surface for `com.kaspaguy.kaspachat.android.core.NativeCore`. Secrets cross as byte arrays (never Strings,
//! except the phrase on its way to the screen) and every Rust-side copy is wiped before returning. Errors become
//! IllegalArgumentException carrying only the error kind, never the input.

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use zeroize::Zeroize;

use kaspaveil_wire::Error;

fn bytes(env: &JNIEnv, a: &JByteArray) -> Vec<u8> {
    env.convert_byte_array(a).unwrap_or_default()
}

fn out(env: &mut JNIEnv, r: Result<Vec<u8>, Error>) -> jbyteArray {
    match r {
        Ok(mut v) => {
            let a = env.byte_array_from_slice(&v).map(|a| a.into_raw()).unwrap_or(std::ptr::null_mut());
            v.zeroize();
            a
        }
        Err(e) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", e.to_string());
            std::ptr::null_mut()
        }
    }
}

fn out_str(env: &mut JNIEnv, r: Result<String, Error>) -> jstring {
    match r {
        Ok(mut s) => {
            let j = env.new_string(&s).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut());
            s.zeroize();
            j
        }
        Err(e) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_mnemonicFromEntropy(mut env: JNIEnv, _: JClass, entropy: JByteArray) -> jstring {
    let mut e = bytes(&env, &entropy);
    let r = crate::mnemonic_from_entropy(&e);
    e.zeroize();
    out_str(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_seedFromMnemonic(mut env: JNIEnv, _: JClass, phrase: JByteArray) -> jbyteArray {
    let mut p = bytes(&env, &phrase);
    let r = std::str::from_utf8(&p).map_err(|_| Error::Mnemonic).and_then(crate::seed_from_mnemonic).map(|s| s.to_vec());
    p.zeroize();
    out(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_isValidMnemonic(env: JNIEnv, _: JClass, phrase: JByteArray) -> jboolean {
    let mut p = bytes(&env, &phrase);
    let ok = std::str::from_utf8(&p).ok().map(|s| crate::seed_from_mnemonic(s).map(|mut s| s.zeroize()).is_ok()).unwrap_or(false);
    p.zeroize();
    if ok { JNI_TRUE } else { JNI_FALSE }
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_ownerPub(mut env: JNIEnv, _: JClass, seed: JByteArray) -> jbyteArray {
    let mut s = bytes(&env, &seed);
    let r = crate::owner_pub(&s).map(|k| k.to_vec());
    s.zeroize();
    out(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_defaultName(mut env: JNIEnv, _: JClass, owner: JByteArray, n: jint) -> jstring {
    let o = bytes(&env, &owner);
    let r = u8::try_from(n).map_err(|_| Error::Malformed).and_then(|n| crate::default_name(&o, n));
    out_str(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_registryBucket(mut env: JNIEnv, _: JClass, name: JString) -> jint {
    let n: String = env.get_string(&name).map(|s| s.into()).unwrap_or_default();
    crate::registry_bucket(&n) as jint
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_bundlePublication(
    mut env: JNIEnv,
    _: JClass,
    seed: JByteArray,
    spk_id: jint,
    created_sec: jlong,
    aux: JByteArray,
) -> jbyteArray {
    let mut s = bytes(&env, &seed);
    let a = bytes(&env, &aux);
    let r = match (u32::try_from(spk_id), u64::try_from(created_sec)) {
        (Ok(id), Ok(c)) => crate::bundle_publication(&s, id, c, &a),
        _ => Err(Error::Malformed),
    };
    s.zeroize();
    out(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_claimSecret(mut env: JNIEnv, _: JClass, seed: JByteArray, i: jint) -> jbyteArray {
    let mut s = bytes(&env, &seed);
    let r = u32::try_from(i).map_err(|_| Error::Malformed).map(|i| crate::claim_secret(&s, i).to_vec());
    s.zeroize();
    out(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_extraSecret(mut env: JNIEnv, _: JClass, claim: JByteArray) -> jbyteArray {
    let mut c = bytes(&env, &claim);
    let r = Ok(crate::extra_secret(&c).to_vec());
    c.zeroize();
    out(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_localKey(mut env: JNIEnv, _: JClass, seed: JByteArray, label: JString) -> jbyteArray {
    let mut s = bytes(&env, &seed);
    let l: String = env.get_string(&label).map(|s| s.into()).unwrap_or_default();
    let r = Ok(crate::local_key(&s, &l).to_vec());
    s.zeroize();
    out(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_vaultKey(mut env: JNIEnv, _: JClass, passcode: JByteArray, salt: JByteArray) -> jbyteArray {
    let mut p = bytes(&env, &passcode);
    let salt = bytes(&env, &salt);
    let r = Ok(crate::vault_key(&p, &salt).to_vec());
    p.zeroize();
    out(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_vaultSeal(mut env: JNIEnv, _: JClass, key: JByteArray, iv: JByteArray, plain: JByteArray) -> jbyteArray {
    let mut k = bytes(&env, &key);
    let iv = bytes(&env, &iv);
    let mut p = bytes(&env, &plain);
    let r = crate::vault_seal(&k, &iv, &p);
    k.zeroize();
    p.zeroize();
    out(&mut env, r)
}

/// Returns null (no exception) on a wrong passcode, so the caller can count attempts.
#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_vaultOpen(mut env: JNIEnv, _: JClass, key: JByteArray, iv: JByteArray, ct: JByteArray) -> jbyteArray {
    let mut k = bytes(&env, &key);
    let iv = bytes(&env, &iv);
    let ct = bytes(&env, &ct);
    let r = crate::vault_open(&k, &iv, &ct);
    k.zeroize();
    match r {
        Err(Error::Aead) => std::ptr::null_mut(),
        r => out(&mut env, r),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_solvePow(
    mut env: JNIEnv,
    _: JClass,
    challenge: JByteArray,
    bits: jint,
    start: jlong,
    count: jlong,
) -> jstring {
    let c = bytes(&env, &challenge);
    match crate::solve_pow(&c, bits.max(0) as u32, start.max(0) as u64, count.max(0) as u64) {
        Some(n) => out_str(&mut env, Ok(n)),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_bundleTag(mut env: JNIEnv, _: JClass, owner: JByteArray) -> jbyteArray {
    let o = bytes(&env, &owner);
    let r = crate::bundle_tag(&o).map(|t| t.to_vec());
    out(&mut env, r)
}

/// -1 when the payload is not a valid, current bundle publication by this owner.
#[no_mangle]
pub extern "system" fn Java_com_kaspaguy_kaspachat_android_core_NativeCore_ownBundleSpkId(env: JNIEnv, _: JClass, payload: JByteArray, owner: JByteArray, now_sec: jlong) -> jlong {
    let p = bytes(&env, &payload);
    let o = bytes(&env, &owner);
    crate::own_bundle_spk_id(&p, &o, now_sec.max(0) as u64).map(|id| id as jlong).unwrap_or(-1)
}
