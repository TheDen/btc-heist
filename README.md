# btc-heist

Brute-forces Bitcoin wallets by generating both random BIP39 mnemonics (BIP44 HD wallets) and raw private keys (including pre-HD uncompressed keys), checking all derived addresses against a known set of funded addresses.

## Setup

Download the latest list of all funded BTC addresses:

```bash
make fetch
```

Build the binary:

```bash
make build
```

## Running

```bash
./bin/btc-heist
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
