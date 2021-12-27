# btc-heist


## Running

Install deps, i.e., `python3 -m pip install -r requirements.txt`

Download the [CSV dump of all bitcoin addresses with a balance](https://bitkeys.work/download.php) and `cut` the first column to make a file of BTC address

```bash
wget 'https://bitkeys.work/btc_balance_sorted.csv'
cut -d, -f 1 btc_balance_sorted.csv | grep -v address > public_addresses_sorted.txt
```

then run `python3 btc-heist.py`


```
usage: btc-heist.py [-h] [-c CORES] [-f ADDRESSES] [-o KEYFILE]

optional arguments:
  -h, --help            show this help message and exit
  -c CORES, --cores CORES
                        Number of CPU cores to use (default: 4)
  -f ADDRESSES, --addresses ADDRESSES
                        File containing BTC addresses (default: public_addresses_sorted.txt),
  -o KEYFILE, --keyfile KEYFILE
                        File to output found keys (default: found_keys.txt)
```