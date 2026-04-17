<div align="center">

# btc-heist

![Go Version](https://img.shields.io/github/go-mod/go-version/TheDen/btc-heist?style=flat-square&logo=go)
[![License](https://img.shields.io/github/license/TheDen/btc-heist?style=flat-square)](/LICENSE)

</div>
<div align="center">
Brute-forces Bitcoin wallets by generating both random BIP39 mnemonics (BIP44 HD wallets) and raw private keys (including pre-HD uncompressed keys), checking all derived addresses against a known set of funded addresses.
</div>

## Setup

### Prerequisites

- Go 1.21+
- `curl` and `gunzip` (standard on macOS/Linux)

### Download the address list

The address list is sourced from [loyce.club](http://addresses.loyce.club/) — a regularly updated dataset of all known funded Bitcoin addresses (~50 million entries).

```bash
make fetch
```

This downloads `Bitcoin_addresses_LATEST.txt.gz` from `http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz`, decompresses it, and saves it as `Bitcoin_addresses_LATEST.txt` in the project root. The file is large (~1 GB uncompressed); loading it into the Bloom filter and map at startup takes a few seconds.

### Download a prebuilt binary

Grab the latest release for your platform from
[GitHub Releases](https://github.com/TheDen/btc-heist/releases/latest).

### Or Build

```bash
make build
```

The binary is written to `bin/btc-heist`.

## Running

```bash
./bin/btc-heist
```

By default it uses all available CPU cores and checks 50 derived addresses per mnemonic. Progress is printed every 5 seconds:

```
[5s] 42301 keys/s  total: 211505  matched: 0
```

## Options

```
  -c int    number of CPU cores to use (default: all cores)
  -f string file containing BTC addresses (default: Bitcoin_addresses_LATEST.txt)
  -n uint   addresses to check per mnemonic (default: 50)
  -o string output file for found keys (default: found_keys.txt)
```

## Output

Matches are appended to `found_keys.txt`. BIP39 wallet matches are written as:

```
mnemonic=<words> address=<address>
```

Raw private key matches are written as:

```
wif=<WIF-encoded-key> address=<address>
```
