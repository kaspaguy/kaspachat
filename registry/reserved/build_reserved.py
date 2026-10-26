#!/usr/bin/env python3
"""Build the Plus reserved-name list: names held back for auction, protected, or blocked.

Precedence: blocked > protected > auction. Pattern rules (short names, pure digits) are
enforced by the bouncer and are not enumerated here.

Sources are pinned: the builder reads only the snapshot in .cache/ (taken 2026-09-29) and checks it against
.cache/SHA256SUMS, so a rebuild gives the same list on any machine. A rebuild can only add
or tighten: every name already in reserved.csv keeps at least its disposition, and every
protection already in patterns.json is kept (audit F1, 2026-10-11).

Usage: build_reserved.py            rebuild from the pinned snapshot
       build_reserved.py --refresh  download the sources again, re-pin them, then rebuild
                                    (review the diff of .cache/SHA256SUMS and reserved.csv)
"""
import argparse
import csv
import hashlib
import json
import os
import re
import sys
import urllib.request
from collections import Counter

SOURCES = {
    "words10k.txt": "https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english-no-swears.txt",
    "firstnames.txt": "https://raw.githubusercontent.com/dominictarr/random-name/master/first-names.txt",
    "countries.json": "https://raw.githubusercontent.com/mledoze/countries/master/countries.json",
    "sp500.csv": "https://raw.githubusercontent.com/datasets/s-and-p-500-companies/main/data/constituents.csv",
    "badwords.txt": "https://raw.githubusercontent.com/LDNOOBW/List-of-Dirty-Naughty-Obscene-and-Otherwise-Bad-Words/master/en",
    "paprika.json": "https://api.coinpaprika.com/v1/coins",
    "words_alpha.txt": "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt",
}

MIN_LEN, MAX_LEN = 1, 20
PATTERN_RULES = [
    ("short", "any name of 1-3 characters", "auction"),
    ("digits", "any all-digit name of 1-4 characters (0-9999, incl. every year)", "auction"),
    ("official-substring", "any name containing kaspaveil, kaspachat, kaspaguy, kasveil, kastalk, official, support, admin, verified or security", "protected"),
    ("kaspa-substring", "any name containing kaspa, kachat, kasia, kbeam or kasplex (kaspachat, mykaspa, kaspa-fan); kasveil/kastalk/kaspaguy are in official-substring", "protected"),
    ("crypto-prefix", "any name starting with a cryptocurrency's name (top 500 by rank, names of 5+ characters that aren't common words; hyphens ignored): bitcoin-anything, ethereum-anything", "protected"),
    ("brand-suffix", "a protected crypto brand followed by a service word (official, support, admin, verified, security, wallet, app, hq, team, help, chat, pay, swap, dex, ...), with or without a hyphen: kaschat, btc-pay, eth-wallet, binance-hq, kasware-team. Brands: every cryptocurrency ticker of 3+ characters (top 500, incl. kas; common-word tickers only in the top 25), Kaspaguy's list (btc eth usdt usdc bnb sol xrp ada doge ton; binance coinbase kraken okx bybit kucoin gate htx bitfinex), every listed exchange/wallet and every Kaspa-ecosystem name", "protected"),
]

# Service words that turn a ticker into something that looks like an official product ("kaschat", "btc-wallet").
# Named by Kaspaguy 2026-09-29: always brands, even when they are also ordinary words (gate, ton, sol).
ANDY_EXCHANGES = "binance coinbase kraken okx bybit kucoin gate htx bitfinex".split()
ANDY_TOKENS = "BTC ETH USDT USDC BNB SOL XRP ADA DOGE TON".split()
ANDY_KASPA = "kaspa kaspachat kaspaveil kasveil kachat kasia kbeam kaspaguy kasplex".split()

SERVICE_SUFFIXES = """official support admin admins verified security hq team help chat chats talk msg message messenger mail pay pays payment wallet wallets swap swaps dex cex app apps bank fi finance
fund funds dao coin coins token tokens cash net network org io official team support help news hub labs lab miner miners mining
pool pools bridge nft nfts market markets exchange trade trader trading explorer scan node nodes dev devs foundation community
army whale whales club world global live tv pro plus vip bot bots id name names domain domains vault staking stake earn yield
lend loan loans card cards store shop mart game games bet casino""".split()

OFFICIAL = """kaspaveil kaspachat kasveil kastalk kaspaguy kasguy duskswap admin administrator root system sysadmin support help
helpdesk security official staff team mod mods moderator moderators bot bots api www web mail email info news status abuse
legal privacy terms billing payment payments pay treasury auction auctions verify verified verification wallet wallets faucet
relay indexer registry owner dev devs developer developers null undefined anonymous everyone here all test testing demo example
guest user users noreply no-reply postmaster webmaster hostmaster contact sales marketing press media jobs careers service services
account accounts login logout signup sign-up register settings notification notifications announcement announcements update updates
backup recovery reset password passwords report reports spam phishing scam scams fraud safety trust trustandsafety compliance
app apps download downloads ios android desktop web-app plus premium pro free subscribe subscription credits tokens blind
kaspaguy-official kaspaveil-official kaspachat-official kasveil-official kastalk-official""".split()

KASPA_ECOSYSTEM = """kaspa kaspanet kaspa-org kaspaorg kaspafoundation kaspa-foundation kas-fyi kasfyi kaspium kasware kasia kbeam
kasplex kaspacom kaspa-com kasswap zealous zealousswap igra igralabs igra-labs kaspa-ng kaspang kastle kasmedia kaspaexplorer
kaspa-explorer rusty-kaspa rustykaspa silverscript toccata crescendo dagknight ghostdag daglabs sompolinsky kasbay kaspdex
kaspadao kaspa-dao kaspafinance kasfinance kaspa-wallet kaspawallet kaspaindustrial vprogs argent kasatomic
kaspachat kachat kaschat kas-chat kaspa-chat kasmsg kastalk kasmail kaspamail""".split()

KASPA_LINGO = """sompi sompis blockdag dag dags kaspian kaspians kasper ghost ghosts knight knights silver kas-silver phantom
tenbps 10bps hundredbps 100bps heavyhash kheavyhash pow proofofwork fairlaunch fair-launch nopremine""".split()

EXCHANGES_WALLETS = """binance coinbase kraken kucoin okx okex bybit bitget gateio gate-io mexc htx huobi bitfinex bitstamp gemini
upbit bithumb bitflyer cryptocom crypto-com robinhood etoro bitmart lbank bingx phemex deribit bitpanda uphold coinex poloniex
hyperliquid uniswap pancakeswap sushiswap curve aave lido metamask ledger trezor trustwallet trust-wallet exodus phantomwallet
tangem safepal chainge coinmarketcap coingecko tradingview etherscan blockchaincom blockchain-com kasplexwallet okxwallet
bitvavo coinone korbit bitkub zipmex indodax wazirx coindcx coinswitch mudrex luno paxful localbitcoins bisq hodlhodl
changenow changelly fixedfloat sideshift trocador cyphergoat eigenwallet unstoppable""".split()

BRANDS = """google alphabet youtube gmail android apple iphone ipad macbook icloud microsoft windows xbox outlook amazon aws alexa
meta facebook instagram whatsapp messenger threads telegram signal discord twitter tiktok bytedance snapchat reddit linkedin
pinterest tumblr netflix spotify paypal venmo cashapp visa mastercard amex americanexpress stripe wise revolut tesla spacex
starlink nvidia intel amd qualcomm samsung sony nintendo playstation nike adidas puma cocacola coca-cola pepsi mcdonalds
starbucks disney marvel pixar openai chatgpt anthropic claude gemini-ai grok xai deepseek mistral perplexity uber airbnb
booking agoda expedia zoom slack dropbox github gitlab cloudflare torproject protonmail proton-mail proton tutanota tuta
threema wickr viber wechat kakao kakaotalk zalo grab shopee lazada alibaba aliexpress tencent baidu huawei xiaomi oppo vivo
oneplus lenovo dell hp hewlettpackard ibm oracle salesforce adobe canva figma notion openclaw hermes chanel gucci louisvuitton
rolex ferrari lamborghini porsche bmw mercedes toyota honda hyundai kia ford chevrolet volkswagen audi redbull heineken
ikea walmart target costco bestbuy ebay etsy shopify wordpress wikipedia mozilla firefox chrome safari opera brave duckduckgo
yahoo bing skype teams whatsappbusiness line-app lineapp kasikorn kbank scb bangkokbank krungthai emirates etihad flydubai
thaiairways airasia agoda-com""".split()

PUBLIC_FIGURES = """vitalik buterin vitalikbuterin saylor michaelsaylor cz changpeng elonmusk elon-musk musk trump donaldtrump biden
obama putin xijinping modi narendramodi pope zelensky macron sunak starmer anwar thaksin srettha paetongtarn mbs mbz
sheikhmohammed jackma zuckerberg markzuckerberg bezos jeffbezos billgates satyanadella sundarpichai timcook samaltman
dariobamodei kamalaharris charles kingcharles taylorswift beyonce cristiano ronaldo messi""".split()

CRYPTO_GENERIC = """crypto cryptos blockchain satoshi nakamoto hodl hodler moon moonshot lambo whale whales degen degens
alpha wagmi ngmi gm gn fomo fud bull bulls bear bears pump dump airdrop airdrops staking stake miner miners mining hash
hashrate block blocks defi nft nfts dao daos dex cex swap swaps token coin coins money cash gold bank banker pay trade trader
traders trading invest investor fund funds vault market markets exchange escrow otc rich wealth profit yield private secret
anon cipher crypt encrypt encrypted veil shadow stealth quantum node nodes validator oracle bridge layer1 layer2 l1 l2 rollup
zk zkp zero-knowledge web3 metaverse meme memecoin shill ape apes diamondhands paperhands rekt btfd buidl mempool genesis
halving sats sat lightning altcoin altcoins stablecoin stablecoins usd eur thb aed gbp jpy cny inr""".split()

LUCKY_NUMBERS = """168 518 520 888 999 777 666 69 420 1337 1314 8888 88888 888888 8888888 88888888 99999 999999 77777 777777
11111 111111 22222 222222 33333 55555 555555 66666 666666 00000 000000 12345 123456 1234567 12345678 123456789 1234567890
54321 654321 987654321 1234 4321 2468 13579 1000000 100000 10000 42069 69420 314159 31415 271828 007 0007 101 404 911""".split()

CITIES = """bangkok pattaya phuket chiangmai chiang-mai krabi huahin kohsamui dubai abudhabi sharjah doha riyadh jeddah london
paris berlin madrid rome milan amsterdam zurich geneva vienna prague warsaw moscow istanbul tbilisi kutaisi batumi athens
lisbon dublin stockholm oslo copenhagen helsinki newyork new-york nyc losangeles la sanfrancisco miami chicago lasvegas
vegas toronto vancouver montreal mexico mexicocity saopaulo rio buenosaires lima bogota tokyo osaka kyoto seoul busan beijing
shanghai shenzhen hongkong macau taipei singapore kualalumpur jakarta bali manila hanoi saigon hochiminh phnompenh yangon
mumbai delhi newdelhi bangalore bengaluru chennai kolkata hyderabad karachi lahore dhaka colombo kathmandu cairo lagos
nairobi johannesburg capetown casablanca sydney melbourne brisbane perth auckland telaviv jerusalem""".split()


def norm_variants(raw):
    s = raw.lower().replace("&", " and ").replace("'", "").replace("’", "")
    s = re.sub(r"[^a-z0-9]+", " ", s).strip()
    if not s:
        return set()
    parts = s.split()
    out = {"".join(parts)}
    if len(parts) > 1:
        out.add("-".join(parts))
    return {v for v in out if MIN_LEN <= len(v) <= MAX_LEN}


def company_name(name):
    n = re.sub(r"\(.*?\)", "", name)
    n = re.sub(r"\b(inc|incorporated|corporation|corp|company|co|holdings|holding|group|plc|ltd|limited|the|class [a-z]|n\.v\.|s\.a\.|ag|se|llc|lp)\b\.?", " ", n, flags=re.I)
    return n.replace(",", " ").strip()


def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def fetch(cache):
    os.makedirs(cache, exist_ok=True)
    for fn, url in SOURCES.items():
        req = urllib.request.Request(url, headers={"User-Agent": "kaspaveil-reserved-builder"})
        with urllib.request.urlopen(req, timeout=60) as r, open(os.path.join(cache, fn), "wb") as f:
            f.write(r.read())
    with open(os.path.join(cache, "SHA256SUMS"), "w") as f:
        for fn in sorted(SOURCES):
            f.write(f"{sha256(os.path.join(cache, fn))}  {fn}\n")


def verify(cache):
    sums = os.path.join(cache, "SHA256SUMS")
    if not os.path.exists(sums):
        sys.exit(f"no pinned sources in {cache}: run with --refresh once, then commit .cache/")
    pinned = dict(reversed(line.split()) for line in open(sums) if line.strip())
    if set(pinned) != set(SOURCES):
        sys.exit(".cache/SHA256SUMS doesn't list exactly the sources the builder uses")
    for fn, h in pinned.items():
        if sha256(os.path.join(cache, fn)) != h:
            sys.exit(f"{fn} doesn't match .cache/SHA256SUMS: the pinned snapshot was changed")


def previous(here):
    """The list and patterns as committed, so a rebuild can't drop a protection."""
    rows, pats = {}, None
    if os.path.exists(os.path.join(here, "reserved.csv")):
        for name, category, disposition in list(csv.reader(open(os.path.join(here, "reserved.csv"), encoding="utf-8")))[1:]:
            rows[name] = (category, disposition)
    if os.path.exists(os.path.join(here, "patterns.json")):
        pats = json.load(open(os.path.join(here, "patterns.json")))
    return rows, pats


def main(cache, refresh):
    if refresh:
        fetch(cache)
    verify(cache)
    here = os.path.dirname(os.path.abspath(__file__))
    old_rows, old_pats = previous(here)
    entries = {}
    rank = {"blocked": 3, "protected": 2, "auction": 1}

    def add(raw_names, category, disposition, expand=True):
        for raw in raw_names:
            for v in (norm_variants(raw) if expand else {raw}):
                cur = entries.get(v)
                if cur is None or rank[disposition] > rank[cur[1]]:
                    entries[v] = (category, disposition)

    rd = lambda fn: open(os.path.join(cache, fn), encoding="utf-8", errors="ignore").read()

    add(rd("badwords.txt").split("\n"), "offensive", "blocked")
    add(OFFICIAL, "official-system", "protected")
    add(KASPA_ECOSYSTEM + ANDY_KASPA, "kaspa-ecosystem", "protected")
    add(ANDY_EXCHANGES, "exchange-wallet", "protected")
    add(ANDY_TOKENS, "crypto-ticker", "protected")
    add(EXCHANGES_WALLETS, "exchange-wallet", "protected")
    add(BRANDS, "brand", "protected")
    sp500 = [company_name(r["Security"]) for r in csv.DictReader(open(os.path.join(cache, "sp500.csv"), encoding="utf-8"))]
    add(PUBLIC_FIGURES, "public-figure", "protected")
    coins = [c for c in json.load(open(os.path.join(cache, "paprika.json"))) if c.get("rank") and c.get("is_active")]
    coins.sort(key=lambda c: c["rank"])
    add([c["name"] for c in coins[:25]], "crypto-project-top25", "protected")
    common = set()
    for lst in (rd("words10k.txt").split("\n"), rd("firstnames.txt").split("\n"), CRYPTO_GENERIC, KASPA_LINGO, CITIES):
        for raw in lst:
            common |= norm_variants(raw)
    soft = lambda names: [n for n in names if not (norm_variants(n) & common)]
    add(soft([c["name"] for c in coins[25:500]]), "crypto-project", "protected")
    add(soft([c["symbol"] for c in coins[:500]]), "crypto-ticker", "protected")
    add(soft(sp500), "brand-sp500", "protected")
    # Pattern data for the bouncer (crypto-prefix and ticker-suffix rules).
    prefixes = sorted({v.replace("-", "") for n in soft([c["name"] for c in coins[:500]]) + ["Bitcoin", "Kaspa"] for v in norm_variants(n)
                       if len(v.replace("-", "")) >= 5})
    # A prefix that starts an ordinary word ("aster" -> "asterisk") only reserves itself, not everything after it.
    english = {w.strip() for w in rd("words_alpha.txt").split("\n") if w.strip()} | common
    # A name that begins with an English word which merely starts with a coin name ("asterisk" / aster) is not that coin.
    extensions = {p: sorted(w for w in english if w.startswith(p) and w != p) for p in prefixes}
    extensions = {p: ws for p, ws in extensions.items() if ws}
    # Tickers: the top 25 always (SOL, LINK, ...), the rest only when they aren't common words.
    raw_tickers = soft([c["symbol"] for c in coins[:500]]) + [c["symbol"] for c in coins[:25]] + ANDY_TOKENS + ["KAS"]
    stems = {v for t in raw_tickers for v in norm_variants(t) if len(v) >= 3 and "-" not in v}
    stems |= {v.replace("-", "") for n in EXCHANGES_WALLETS + ANDY_EXCHANGES + KASPA_ECOSYSTEM + ANDY_KASPA for v in norm_variants(n)}
    tickers = sorted(stems)
    allow = sorted(t + x for t in tickers for x in SERVICE_SUFFIXES if t + x in english)
    add(KASPA_LINGO, "kaspa-lingo", "auction")
    add(CRYPTO_GENERIC, "crypto-generic", "auction")
    add(LUCKY_NUMBERS, "numbers", "auction", expand=False)
    add(CITIES, "city", "auction")
    countries = json.load(open(os.path.join(cache, "countries.json"), encoding="utf-8"))
    add([c["name"]["common"] for c in countries], "country", "auction")
    add([cap for c in countries for cap in c.get("capital", [])], "capital", "auction")
    add(rd("firstnames.txt").split("\n"), "first-name", "auction")
    add(rd("words10k.txt").split("\n"), "dictionary", "auction")

    # Only add or tighten: names from the committed list keep at least their disposition; protections
    # (substrings, prefixes, tickers, service words) are united; exemptions (allow, extensions) survive
    # only where both the committed and the new build grant them.
    for name, (category, disposition) in old_rows.items():
        cur = entries.get(name)
        if cur is None or rank[disposition] > rank[cur[1]]:
            entries[name] = (category, disposition)
    substrings = ["kaspa", "kachat", "kasia", "kbeam", "kasplex"]
    suffixes = list(SERVICE_SUFFIXES)
    if old_pats:
        substrings = old_pats["substrings"] + [x for x in substrings if x not in old_pats["substrings"]]
        suffixes = old_pats["suffixes"] + [x for x in suffixes if x not in old_pats["suffixes"]]
        tickers = sorted(set(tickers) | set(old_pats["tickers"]))
        allow = sorted(set(allow) & set(old_pats["allow"]))
        old_ext = old_pats["extensions"]
        merged = {}
        for p in sorted(set(prefixes) | set(old_pats["prefixes"])):
            if p in extensions and p in old_ext:
                ws = sorted(set(extensions[p]) & set(old_ext[p]))
            else:
                ws = extensions.get(p) or old_ext.get(p) or []
            if ws:
                merged[p] = ws
        prefixes = sorted(set(prefixes) | set(old_pats["prefixes"]))
        extensions = merged
    json.dump({"substrings": substrings, "prefixes": prefixes, "tickers": tickers, "suffixes": suffixes, "allow": allow, "extensions": extensions},
              open(os.path.join(here, "patterns.json"), "w"), indent=0)
    rows = sorted((n, c, d) for n, (c, d) in entries.items())
    with open(os.path.join(here, "reserved.csv"), "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["name", "category", "disposition"])
        w.writerows(rows)
    by_disp = Counter(d for _, _, d in rows)
    by_cat = Counter((c, d) for _, c, d in rows)
    with open(os.path.join(here, "SUMMARY.md"), "w") as f:
        f.write("# Plus reserved names — summary (generated by build_reserved.py)\n\n")
        f.write(f"**{len(rows):,} enumerated names**: " + ", ".join(f"{d} {n:,}" for d, n in sorted(by_disp.items())) + "\n\n")
        f.write("## Pattern rules (enforced by the bouncer, not enumerated)\n\n| Rule | Covers | Disposition |\n|---|---|---|\n")
        for name, desc, disp in PATTERN_RULES:
            f.write(f"| {name} | {desc} | {disp} |\n")
        f.write("\n## Enumerated names by category\n\n| Category | Disposition | Names |\n|---|---|---|\n")
        for (c, d), n in sorted(by_cat.items(), key=lambda x: (-rank[x[0][1]], -x[1])):
            f.write(f"| {c} | {d} | {n:,} |\n")
        f.write("\nDispositions: **auction** = held for Kaspaguy auctions / later release; **protected** = never auctioned, "
                "released only to a verified owner (brands, projects, officials, public figures); **blocked** = never issued.\n")
    print(len(rows), dict(by_disp))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build the Plus reserved-name list from the pinned sources.")
    ap.add_argument("--refresh", action="store_true", help="download the sources again and re-pin them before building")
    a = ap.parse_args()
    main(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache"), a.refresh)
