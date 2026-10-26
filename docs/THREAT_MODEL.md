# What KaspaChat hides, and what it doesn't

This is a plain summary. The full text is in `PROTOCOL_SPEC.md` §1 and §6; if the two differ, the specification is right.

## What the code lets you check
- **The encryption, the 30-hour deletion and the device vault** are in `protocol/` and have byte-exact test vectors, checked by an independent Rust implementation (`rust-impl/`).
- **The money rules**: the 25/75 split, "nobody can seize a name", "nobody can withdraw from the treasury" are in `contracts/`, and the bytecode is on-chain.
- **The apps and servers** are in this repository. Web builds are served fresh on every visit, so for the web app compare the served files with the published build hash; the native apps remove that weakness.

## What can't be checked from source
- That a server you connect to runs exactly this code. Run your own relay or indexer if that matters to you.
- That an operator keeps no logs. The project's own servers keep no IP logs, but a client can't verify that, which is why the native apps use Tor by default.

## Hidden
- **Content**: only the participants can read a message. The operator holds no keys.
- **Who talks to whom**: recipients are never on-chain; when you send through the relay your wallet isn't either.
- **Past and future messages** after a key theft (forward secrecy and recovery).
- **Harvest now, decrypt later**: the key exchange is hybrid post-quantum.
- **Key substitution**: name to key bindings are committed on-chain.

## Not hidden
- **Your IP address, from the relay and indexer you connect to**, unless you use Tor (default in the desktop and Android apps; the web app on clearnet gets only the relay's timing mix).
- **Sending from your own wallet** instead of through the relay exposes that wallet's address to anyone reading the chain.
- **Timing**: a message appears on-chain when sent; a global observer may correlate it with online activity.
- **Inbox bucket counts**: there are 4,096 shared buckets. With few users, a bucket can hold one person, so a watcher might learn that someone was contacted. Cover traffic sends dummy first contacts to blur this.
- **Names are public**: the registry says a name exists and which key owns it.
- **The ciphertext is public and permanent on the chain.** The 30-hour deletion removes messages from devices, not the encrypted data from the chain.
- **A compromised device** reads whatever its owner reads.
- **The bouncer can issue prepaid months without payment** (it can't seize, delete or read anything). The counters are on-chain so anyone can compare them with the money received.

## Not claimed
KaspaChat is not "untraceable" or "unhackable", and it has had no paid third-party audit. Trust comes from the open code, the second implementation, the test vectors, and public review.
