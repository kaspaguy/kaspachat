// Kaspaveil root-key ceremony: 2-of-3 FROST (BIP-340 / Taproot ciphersuite) for the treasury root key,
// and signing a relay-key replacement for the treasury's spending pot. Each holder runs their own steps on their own device; only the files
// named below travel between devices. See tools/ceremony/RUNBOOK.md.
//
//   dkg1  <me> <priv> <xfer>                  -> xfer/dkg1-from-<me>.json                 (broadcast to both others)
//   dkg2  <me> <priv> <xfer>                  -> xfer/dkg2-from-<me>-to-<j>.json          (SECRET: hand only to holder j)
//   dkg3  <me> <priv> <xfer>                  -> priv/key.json (SECRET share), xfer/group-from-<me>.json; prints the root key
//   commit <me> <priv> <xfer>                 -> priv/nonce.json (SECRET, single use), xfer/commit-from-<me>.json
//   package <xfer> <potCov> <newRelayPub> <nonce> <i> <j> -> xfer/package.json (coordinator; public)
//   sign  <me> <priv> <xfer>                  -> xfer/share-from-<me>.json; deletes priv/nonce.json
//   aggregate <xfer>                          -> xfer/replace-<nonce>.hex, verified against the root key
//
// Share repair (Repairable Threshold Scheme, eprint 2017/1155): the two remaining holders rebuild a lost share
// for holder <lost> without ever reconstructing the root key, and without either of them learning the share.
//   repair1 <me> <priv> <xfer> <lost> <other>  -> priv/repair-delta.json (SECRET), xfer/repair1-from-<me>-to-<other>.json (SECRET: hand only to <other>)
//   repair2 <me> <priv> <xfer> <lost> <other>  -> xfer/repair2-from-<me>-to-<lost>.json (SECRET: hand only to <lost>)
//   repair3 <me> <priv> <xfer> <a> <b>         -> priv/key.json, checked against the group's public record; prints the root key
//
// Share refresh (proactive rotation): all three holders swap to fresh shares of the SAME root key, so every old
// share (including a stolen copy) becomes worthless. The threshold can't change (CVE-2025-58359 class; checked).
//   refresh1 <me> <priv> <xfer>   -> priv/refresh1.secret.json, xfer/refresh1-from-<me>.json   (broadcast)
//   refresh2 <me> <priv> <xfer>   -> xfer/refresh2-from-<me>-to-<j>.json                     (SECRET: hand only to holder j)
//   refresh3 <me> <priv> <xfer>   -> priv/key.new.json, xfer/group-refreshed-from-<me>.json; prints the root key (must be unchanged)
//   refresh-commit <me> <priv> <xfer>  (only after all three confirmed the root key) -> new share becomes priv/key.json; old one deleted
use frost_secp256k1_tr as frost;
use frost::keys::dkg::{round1, round2};
use frost::keys::repairable::{Delta, Sigma};
use frost::keys::{KeyPackage, PublicKeyPackage, VerifyingShare};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const HOLDERS: u16 = 3;
const THRESHOLD: u16 = 2;

#[derive(serde::Serialize, serde::Deserialize)]
struct Package {
    pot_cov: String,
    new_relay: String,
    nonce: u64,
    digest: String,
    signing: SigningPackage,
}

fn id(n: u16) -> Identifier {
    assert!((1..=HOLDERS).contains(&n), "holder number must be 1, 2 or 3");
    n.try_into().unwrap()
}

// A secret file is owner-only before any byte of it is written (created 600; an existing file is narrowed first).
fn write<T: Serialize>(path: PathBuf, v: &T, secret: bool) {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    if secret {
        o.mode(0o600);
    }
    let mut f = o.open(&path).expect("write");
    if secret {
        f.set_permissions(std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    f.write_all(&serde_json::to_vec_pretty(v).unwrap()).expect("write");
    println!("wrote {}{}", path.display(), if secret { "  (SECRET)" } else { "" });
}

fn read<T: DeserializeOwned>(path: PathBuf) -> T {
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|_| panic!("missing {}", path.display()))).expect("parse")
}

fn others(me: u16) -> impl Iterator<Item = u16> {
    (1..=HOLDERS).filter(move |&j| j != me)
}

// The root key the treasury contract is compiled with: the x-only form of the (BIP-341-tweaked) group key.
fn root_xonly(group: &PublicKeyPackage) -> [u8; 32] {
    let sec1 = group.verifying_key().serialize().expect("key");
    sec1[1..33].try_into().unwrap()
}

// What the root signs to replace the pot's relay key (contracts/treasury_hot.sil, replaceRelay):
// BLAKE2b-256("kasveil/v1/relay-replace" || pot covenant ID || new relay key || nonce as 8 LE bytes).
fn replace_digest(pot_cov: &[u8], new_relay: &[u8], nonce: u64) -> [u8; 32] {
    let mut m = b"kasveil/v1/relay-replace".to_vec();
    m.extend(pot_cov);
    m.extend(new_relay);
    m.extend(nonce.to_le_bytes());
    blake2b_simd::Params::new().hash_length(32).hash(&m).as_bytes().try_into().unwrap()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let cmd = a.get(1).map(String::as_str).unwrap_or("");
    let me = || a[2].parse::<u16>().expect("holder number");
    let priv_dir = || Path::new(&a[3]).to_path_buf();
    let xfer = |i: usize| Path::new(&a[i]).to_path_buf();
    let mut rng = rand::rngs::OsRng;
    match cmd {
        "dkg1" => {
            let (secret, public) = frost::keys::dkg::part1(id(me()), HOLDERS, THRESHOLD, &mut rng).expect("dkg1");
            write(priv_dir().join("dkg1.secret.json"), &secret, true);
            write(xfer(4).join(format!("dkg1-from-{}.json", me())), &public, false);
        }
        "dkg2" => {
            let secret: round1::SecretPackage = read(priv_dir().join("dkg1.secret.json"));
            let r1: BTreeMap<Identifier, round1::Package> =
                others(me()).map(|j| (id(j), read(xfer(4).join(format!("dkg1-from-{j}.json"))))).collect();
            let (secret2, outgoing) = frost::keys::dkg::part2(secret, &r1).expect("dkg2");
            write(priv_dir().join("dkg2.secret.json"), &secret2, true);
            for j in others(me()) {
                write(xfer(4).join(format!("dkg2-from-{}-to-{j}.json", me())), &outgoing[&id(j)], true);
            }
            std::fs::remove_file(priv_dir().join("dkg1.secret.json")).unwrap();
        }
        "dkg3" => {
            let secret2: round2::SecretPackage = read(priv_dir().join("dkg2.secret.json"));
            let r1: BTreeMap<Identifier, round1::Package> =
                others(me()).map(|j| (id(j), read(xfer(4).join(format!("dkg1-from-{j}.json"))))).collect();
            let r2: BTreeMap<Identifier, round2::Package> =
                others(me()).map(|j| (id(j), read(xfer(4).join(format!("dkg2-from-{j}-to-{}.json", me()))))).collect();
            let (key, group) = frost::keys::dkg::part3(&secret2, &r1, &r2).expect("dkg3");
            write(priv_dir().join("key.json"), &key, true);
            write(xfer(4).join(format!("group-from-{}.json", me())), &group, false);
            std::fs::remove_file(priv_dir().join("dkg2.secret.json")).unwrap();
            for j in others(me()) {
                let _ = std::fs::remove_file(xfer(4).join(format!("dkg2-from-{j}-to-{}.json", me())));
            }
            println!("ROOT KEY (compare with the other two holders): {}", hex::encode(root_xonly(&group)));
        }
        "commit" => {
            let key: KeyPackage = read(priv_dir().join("key.json"));
            let (nonces, commitments) = frost::round1::commit(key.signing_share(), &mut rng);
            write(priv_dir().join("nonce.json"), &nonces, true);
            write(xfer(4).join(format!("commit-from-{}.json", me())), &commitments, false);
        }
        "package" => {
            let (cov_hex, relay_hex, nonce) = (a[3].clone(), a[4].clone(), a[5].parse::<u64>().expect("nonce"));
            let pot_cov = hex::decode(&cov_hex).expect("pot covenant ID hex");
            assert_eq!(pot_cov.len(), 32, "the pot's covenant ID is 32 bytes");
            let relay_pub = hex::decode(&relay_hex).expect("relay key hex");
            assert_eq!(relay_pub.len(), 32, "relay key must be a 32-byte x-only key");
            let signers = [a[6].parse::<u16>().unwrap(), a[7].parse::<u16>().unwrap()];
            assert_ne!(signers[0], signers[1], "two different holders");
            let commitments: BTreeMap<Identifier, SigningCommitments> =
                signers.iter().map(|&i| (id(i), read(xfer(2).join(format!("commit-from-{i}.json"))))).collect();
            let digest = replace_digest(&pot_cov, &relay_pub, nonce);
            let pkg = Package { pot_cov: cov_hex, new_relay: relay_hex, nonce, digest: hex::encode(digest), signing: SigningPackage::new(commitments, &digest) };
            write(xfer(2).join("package.json"), &pkg, false);
            println!("replace the relay key of pot {} (replacement no. {nonce}) with {}, digest {}", pkg.pot_cov, pkg.new_relay, pkg.digest);
        }
        "sign" => {
            let key: KeyPackage = read(priv_dir().join("key.json"));
            let nonces: SigningNonces = read(priv_dir().join("nonce.json"));
            let pkg: Package = read(xfer(4).join("package.json"));
            // Recompute what is being signed, so a holder never signs a digest they can't read.
            let digest = replace_digest(&hex::decode(&pkg.pot_cov).unwrap(), &hex::decode(&pkg.new_relay).unwrap(), pkg.nonce);
            assert_eq!(hex::encode(digest), pkg.digest, "digest does not match pot + new relay key + nonce");
            assert_eq!(pkg.signing.message(), &digest[..], "signing package message does not match");
            println!("SIGNING: replace the relay key of pot {} (replacement no. {}) with NEW RELAY KEY {}", pkg.pot_cov, pkg.nonce, pkg.new_relay);
            // A nonce must never sign twice: it is gone from disk before it signs, so no crash can leave it for reuse.
            std::fs::remove_file(priv_dir().join("nonce.json")).unwrap();
            let share = frost::round2::sign(&pkg.signing, &nonces, &key).expect("sign (run commit again for a fresh nonce)");
            write(xfer(4).join(format!("share-from-{}.json", me())), &share, false);
        }
        "aggregate" => {
            let pkg: Package = read(xfer(2).join("package.json"));
            let group: PublicKeyPackage = read(
                (1..=HOLDERS).map(|i| xfer(2).join(format!("group-from-{i}.json"))).find(|p| p.exists()).expect("a group-from-*.json"),
            );
            let shares: BTreeMap<Identifier, SignatureShare> = (1..=HOLDERS)
                .filter(|&i| pkg.signing.signing_commitments().contains_key(&id(i)))
                .map(|i| (id(i), read(xfer(2).join(format!("share-from-{i}.json")))))
                .collect();
            let sig = frost::aggregate(&pkg.signing, &shares, &group).expect("aggregate");
            let bytes = sig.serialize().expect("sig");
            let sig64: [u8; 64] = bytes[1..].try_into().or_else(|_| bytes[..].try_into()).expect("64-byte BIP-340 signature");
            // Independent check with the secp256k1 library Kaspa's engine uses.
            let root = secp256k1::XOnlyPublicKey::from_slice(&root_xonly(&group)).unwrap();
            let schnorr = secp256k1::schnorr::Signature::from_slice(&sig64).unwrap();
            let digest: [u8; 32] = hex::decode(&pkg.digest).unwrap().try_into().unwrap();
            secp256k1::SECP256K1.verify_schnorr(&schnorr, &secp256k1::Message::from_digest(digest), &root).expect("BIP-340 verify");
            std::fs::write(xfer(2).join(format!("replace-{}.hex", pkg.nonce)), hex::encode(sig64)).unwrap();
            println!("REPLACEMENT SIGNATURE no. {} verified against root key {}: {}", pkg.nonce, hex::encode(root_xonly(&group)), hex::encode(sig64));
        }
        "repair1" => {
            let (lost, other) = (a[5].parse::<u16>().expect("lost holder"), a[6].parse::<u16>().expect("other helper"));
            assert!(lost != me() && other != me() && other != lost, "three different holder numbers");
            let key: KeyPackage = read(priv_dir().join("key.json"));
            let helpers = [id(me().min(other)), id(me().max(other))];
            let deltas = frost::keys::repairable::repair_share_part1::<frost::Secp256K1Sha256TR, _>(&helpers, &key, &mut rng, id(lost)).expect("repair1");
            write(priv_dir().join("repair-delta.json"), &deltas[&id(me())], true);
            write(xfer(4).join(format!("repair1-from-{}-to-{other}.json", me())), &deltas[&id(other)], true);
        }
        "repair2" => {
            let (lost, other) = (a[5].parse::<u16>().expect("lost holder"), a[6].parse::<u16>().expect("other helper"));
            let mine: Delta = read(priv_dir().join("repair-delta.json"));
            let theirs: Delta = read(xfer(4).join(format!("repair1-from-{other}-to-{}.json", me())));
            let sigma = frost::keys::repairable::repair_share_part2(&[mine, theirs]);
            write(xfer(4).join(format!("repair2-from-{}-to-{lost}.json", me())), &sigma, true);
            std::fs::remove_file(priv_dir().join("repair-delta.json")).unwrap();
            let _ = std::fs::remove_file(xfer(4).join(format!("repair1-from-{other}-to-{}.json", me())));
        }
        "repair3" => {
            let helpers = [a[5].parse::<u16>().expect("helper"), a[6].parse::<u16>().expect("helper")];
            let sigmas: Vec<Sigma> = helpers.iter().map(|h| read(xfer(4).join(format!("repair2-from-{h}-to-{}.json", me())))).collect();
            let group: PublicKeyPackage = read(
                (1..=HOLDERS).map(|i| xfer(4).join(format!("group-from-{i}.json"))).find(|p| p.exists()).expect("a group-from-*.json"),
            );
            let key = frost::keys::repairable::repair_share_part3(&sigmas, id(me()), &group).expect("repair3");
            // The library doesn't check the result; a wrong or dishonest helper value must fail here, not at signing time.
            let expected: &VerifyingShare = group.verifying_shares().get(&id(me())).expect("holder is in the group");
            assert_eq!(key.verifying_share(), expected, "REPAIR FAILED: the rebuilt share does not match the group's public record");
            write(priv_dir().join("key.json"), &key, true);
            for h in helpers {
                let _ = std::fs::remove_file(xfer(4).join(format!("repair2-from-{h}-to-{}.json", me())));
            }
            println!("REPAIRED holder {}; ROOT KEY (compare with the helpers): {}", me(), hex::encode(root_xonly(&group)));
        }
        "refresh1" => {
            let key: KeyPackage = read(priv_dir().join("key.json"));
            assert_eq!(*key.min_signers(), THRESHOLD, "this share's threshold is not 2-of-3");
            let (secret, public) = frost::keys::refresh::refresh_dkg_part1(id(me()), HOLDERS, THRESHOLD, &mut rng).expect("refresh1");
            write(priv_dir().join("refresh1.secret.json"), &secret, true);
            write(xfer(4).join(format!("refresh1-from-{}.json", me())), &public, false);
        }
        "refresh2" => {
            let secret: round1::SecretPackage = read(priv_dir().join("refresh1.secret.json"));
            let r1: BTreeMap<Identifier, round1::Package> =
                others(me()).map(|j| (id(j), read(xfer(4).join(format!("refresh1-from-{j}.json"))))).collect();
            let (secret2, outgoing) = frost::keys::refresh::refresh_dkg_part2(secret, &r1).expect("refresh2");
            write(priv_dir().join("refresh2.secret.json"), &secret2, true);
            for j in others(me()) {
                write(xfer(4).join(format!("refresh2-from-{}-to-{j}.json", me())), &outgoing[&id(j)], true);
            }
            std::fs::remove_file(priv_dir().join("refresh1.secret.json")).unwrap();
        }
        "refresh3" => {
            let secret2: round2::SecretPackage = read(priv_dir().join("refresh2.secret.json"));
            let old_key: KeyPackage = read(priv_dir().join("key.json"));
            let old_group: PublicKeyPackage = read(xfer(4).join(format!("group-from-{}.json", me())));
            let r1: BTreeMap<Identifier, round1::Package> =
                others(me()).map(|j| (id(j), read(xfer(4).join(format!("refresh1-from-{j}.json"))))).collect();
            let r2: BTreeMap<Identifier, round2::Package> =
                others(me()).map(|j| (id(j), read(xfer(4).join(format!("refresh2-from-{j}-to-{}.json", me()))))).collect();
            let root_before = root_xonly(&old_group);
            let (key, group) = frost::keys::refresh::refresh_dkg_shares(&secret2, &r1, &r2, old_group, old_key.clone()).expect("refresh3");
            assert_eq!(root_xonly(&group), root_before, "REFRESH FAILED: the root key changed");
            assert_eq!(*key.min_signers(), THRESHOLD, "REFRESH FAILED: the threshold changed");
            assert_eq!(group.verifying_shares().len(), HOLDERS as usize, "REFRESH FAILED: not all three seats refreshed");
            assert_ne!(key.signing_share(), old_key.signing_share(), "REFRESH FAILED: the share did not change");
            write(priv_dir().join("key.new.json"), &key, true);
            write(xfer(4).join(format!("group-refreshed-from-{}.json", me())), &group, false);
            std::fs::remove_file(priv_dir().join("refresh2.secret.json")).unwrap();
            for j in others(me()) {
                let _ = std::fs::remove_file(xfer(4).join(format!("refresh2-from-{j}-to-{}.json", me())));
            }
            println!("REFRESHED holder {}; ROOT KEY (must be unchanged; compare with the other two): {}", me(), hex::encode(root_before));
            println!("Run refresh-commit only after all three holders have confirmed the same root key.");
        }
        "refresh-commit" => {
            let new_group: PublicKeyPackage = read(xfer(4).join(format!("group-refreshed-from-{}.json", me())));
            for j in others(me()) {
                let theirs: PublicKeyPackage = read(xfer(4).join(format!("group-refreshed-from-{j}.json")));
                assert_eq!(theirs, new_group, "holder {j} ended the refresh with a different group record: do not commit");
            }
            std::fs::rename(priv_dir().join("key.new.json"), priv_dir().join("key.json")).expect("no refreshed share to commit");
            write(xfer(4).join(format!("group-from-{}.json", me())), &new_group, false);
            println!("holder {}: refreshed share is now priv/key.json; the old share is gone. Destroy every backup of the old share.", me());
        }
        _ => eprintln!("usage: dkg1|dkg2|dkg3|commit|package|sign|aggregate|repair1|repair2|repair3|refresh1|refresh2|refresh3|refresh-commit"),
    }
}
