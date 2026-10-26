//! Rough timings (cargo run --release --example bench).
use std::time::Instant;

use kaspaveil_wire::keys::{identity_from_seed, prekey};
use kaspaveil_wire::primitives::{mlkem, x25519};
use kaspaveil_wire::random::OsRandom;

fn time(label: &str, n: u32, mut f: impl FnMut()) {
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    println!("{label:<28} {:>8.1} µs", t.elapsed().as_secs_f64() * 1e6 / n as f64);
}

fn main() {
    let id = identity_from_seed([7; 64]);
    let pk = prekey(&id.seed, 1);
    time("X25519", 2000, || {
        std::hint::black_box(x25519(&id.id_x25519_sk, &pk.x25519_pub).unwrap());
    });
    let (ct, _) = mlkem::encaps(&pk.mlkem_pub, &[1; 32]).unwrap();
    time("ML-KEM-768 keygen+decaps", 500, || {
        std::hint::black_box(mlkem::decaps(&pk.mlkem_seed, &ct).unwrap());
    });
    time("ML-KEM-768 encaps (checked)", 500, || {
        std::hint::black_box(mlkem::encaps(&pk.mlkem_pub, &[1; 32]).unwrap());
    });
    let bundle = kaspaveil_wire::bundle::Bundle::create(
        &id.owner_sk, id.owner_pub, id.id_x25519_pub, 1, pk.x25519_pub, pk.mlkem_pub.clone(), 0, vec![], &[0; 32],
    )
    .unwrap();
    let alice = identity_from_seed([8; 64]);
    let s = kaspaveil_wire::first_contact::Sender {
        owner_pub: alice.owner_pub,
        id_x25519_sk: alice.id_x25519_sk,
        id_x25519_pub: alice.id_x25519_pub,
        name: "alice",
    };
    time("first contact (send)", 200, || {
        std::hint::black_box(kaspaveil_wire::first_contact::send(&s, &bundle, 1, b"hi", &mut OsRandom).unwrap());
    });
    let mut sess = kaspaveil_wire::first_contact::send(&s, &bundle, 1, b"hi", &mut OsRandom).unwrap().session;
    time("ratchet encrypt (2 KB)", 2000, || {
        std::hint::black_box(sess.encrypt(1, b"hello", &mut OsRandom).unwrap());
    });
}
