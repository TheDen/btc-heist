# btc-heist


## Running

Install deps, i.e., `python3 -m pip install -r requirements.txt`

Download the [CSV dump of all bitcoin address with balance](https://bitkeys.work/download.php) and `cut` the first column to make a file of BTC address

```bash
wget 'https://bitkeys.work/btc_balance_sorted.csv'
cut -d, -f 1 btc_balance_sorted.csv | grep -v address > public_addresses_sorted.txt
```
g
then run `python3 btc-heist.py`
