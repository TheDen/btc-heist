import argparse
import progressbar
import csv
import urllib.request
from datetime import datetime
from itertools import count
import multiprocessing
from bitcoin import sha256, privtopub, pubtoaddr
from mnemonic import Mnemonic

btc_addresses_url = "https://bitkeys.work/btc_balance_sorted.csv"
download_filename = "btc_balance_sorted_temp.csv"
pbar = None


def show_progress(block_num, block_size, total_size):
    global pbar
    if pbar is None:
        pbar = progressbar.ProgressBar(maxval=total_size)
        pbar.start()
    downloaded = block_num * block_size
    if downloaded < total_size:
        pbar.update(downloaded)
    else:
        pbar.finish()
        pbar = None


def download_address_csv(btc_addresses_url, download_filename):
    urllib.request.urlretrieve(
        btc_addresses_url,
        download_filename,
        show_progress,
    )


def parse_and_save_csv(download_filename, address_list_filename):
    rows = []
    with open(download_filename, newline="") as csv_file:
        for row in csv.reader(csv_file, delimiter=","):
            if row[0] != "address":
                rows.append(row[0])
    with open(address_list_filename, "w+") as parsed_addresses:
        list(map(lambda item: parsed_addresses.write(f"{item}\n"), rows))


def seek(core, btc_address_queue):
    print(f"Core {core}: Searching for Private Key...")
    mnemo = Mnemonic("english")
    log_rate_iterations = 10000
    start_time = datetime.today().timestamp()

    for iteration in count(1):

        # Generate private + public keys and btc address
        private_key = sha256(mnemo.generate(strength=256))
        public_key = privtopub(private_key)
        btc_address = pubtoaddr(public_key)
        btc_address_queue.put((private_key, public_key, btc_address))

        # log rate
        if (iteration % log_rate_iterations) == 0:
            time_diff = datetime.today().timestamp() - start_time
            print(f"Core {core}: {iteration / time_diff} Key/s")  # 253 Key/s


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--cores",
        default=4,
        type=int,
        help="Number of CPU cores to use (default: 4)",
    )
    parser.add_argument(
        "-f",
        "--addresses",
        default="public_addresses_sorted.txt",
        type=str,
        help="File containing BTC addresses (default: public_addresses_sorted.txt),",
    )
    parser.add_argument(
        "-o",
        "--keyfile",
        default="found_keys.txt",
        type=str,
        help="File to output found keys (default: found_keys.txt)",
    )
    parser.add_argument(
        "-d",
        "--download",
        default=False,
        action="store_true",
        help="Download and parse CSV file of bitcoin addresses",
    )

    args = parser.parse_args()
    cores = args.cores
    addresses_filename = args.addresses
    keyfile = args.keyfile
    download = args.download

    if download:
        print(f"Donloading {btc_addresses_url} as {download_filename}")
        print(btc_addresses_url)
        download_address_csv(btc_addresses_url, download_filename)
        print("Finished downloading")
        print(f"Parsing {download_filename} and saving it as {addresses_filename} ...")
        parse_and_save_csv(download_filename, addresses_filename)

    # generate list of pubkey with BTC
    print(f'Loading "{addresses_filename}"...')
    with open(addresses_filename) as f:
        publist = frozenset(f)  # set() used for O(1) search
    print("Loaded.")

    btc_address_queue = multiprocessing.Queue()

    for core in range(cores):
        process = multiprocessing.Process(target=seek, args=(core, btc_address_queue))
        process.start()

    while True:
        private_key, public_key, btc_address = btc_address_queue.get()

        if f"{btc_address}\n" in publist:
            found_key = f"\nPublic: {public_key} | Private: {private_key} | Address: {btc_address}\n"
            print(found_key)
            with open(keyfile, "a") as f:
                f.write(found_key)
