from datetime import datetime
from itertools import count
import multiprocessing
from bitcoin import sha256, privtopub, pubtoaddr
from mnemonic import Mnemonic

cores = 4
filename = "public_addresses_sorted.txt"
found_keys = "found_keys.txt"


def seek(core, btc_address_queue):
    print(f'Core {core}: Searching for Private Key...')
    mnemo = Mnemonic('english')
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
            print(f'Core {core}: {iteration / time_diff} Key/s')  # 253 Key/s


if __name__ == "__main__":

    # generate list of pubkey with BTC
    print(f'Loading "{filename}"...')
    with open(filename) as f:
        publist = frozenset(f)  # set() used for O(1) search
    print('Loaded.')

    btc_address_queue = multiprocessing.Queue()
    
    for core in range(cores):
        process = multiprocessing.Process(target=seek, args=(core, btc_address_queue))
        process.start()
    
    while True:
        private_key, public_key, btc_address = btc_address_queue.get()

        if btc_address in publist:
            found_key = f"\nPublic: {public_key} | Private: {private_key} | Address: {btc_address}\n"
            print(found_key)
            with open(found_keys, "a") as f:
                f.write(found_key)
