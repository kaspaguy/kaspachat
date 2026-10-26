# Reporting a security problem

Email **dev@kaspaguy.com** with what you found, how to reproduce it, and what you think it allows. Please don't publish it before we've had a chance to fix it; we will tell you when it is safe to. We credit reporters by the name they choose.

## In scope
- The protocol, the wire format and the reference implementations (`protocol/`, `rust-impl/`).
- The covenants in `contracts/`: any way to take money out other than the paths they allow, to seize or change a name, or to break the 25/75 split.
- The apps, relay, indexer, bouncer and swap relay in this repository.
- Anything that lets someone read a message, learn who talks to whom, or link a message to the account that paid for it, beyond what `docs/THREAT_MODEL.md` already says is visible.

## Out of scope
- Things the threat model already states openly (for example that a relay you reach without Tor sees your IP address).
- Attacks that need a compromised phone or computer.
- Denial of service by volume, and social engineering.

## Bounty
A **10,000 KAS** bug bounty pool opens when the contracts go to mainnet. Until then the project runs on testnet and valid reports are credited but not paid. The bands and payout rules will be added here when the pool is funded.

## Safe harbour
Good-faith research within the scope above, on testnet or on your own copy of the code, won't be met with legal action from us.
