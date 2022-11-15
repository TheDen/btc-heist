# btc-heist


## Running

Install deps, i.e., `python3 -m pip install -r requirements.txt`

Download the [lastest list of all funded BTC addresses](http://addresses.loyce.club/)

```bash
wget 'http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz'
gzip -d Bitcoin_addresses_LATEST.txt.gz
```
then run `python3 btc-heist.py`

```
usage: btc-heist.py [-h] [-c CORES] [-f ADDRESSES] [-o KEYFILE]

options:
  -h, --help            show this help message and exit
  -c CORES, --cores CORES
                        Number of CPU cores to use (default: 4)
  -f ADDRESSES, --addresses ADDRESSES
                        File containing BTC addresses (default:
                        Bitcoin_addresses_LATEST.txt),
  -o KEYFILE, --keyfile KEYFILE
                        File to output found keys (default: found_keys.txt)
```