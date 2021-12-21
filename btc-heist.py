#!/usr/bin/python3

import os
import time
import datetime as dt
import multiprocessing
from bitcoin import *
from mnemonic import Mnemonic

cores = 4


def seek(core):
    filename = "public_addresses_sorted.txt"
    found_keys = "found_keys.txt"
    log_rate_iterations = 10000
    global num_threads
    start_time = dt.datetime.today().timestamp()
    mnemo = Mnemonic("english")

    print(f"Core {core}: loading file...")
    # Open file in memory as a set so searching is O(1)
    with open(filename) as f:
        publist = set(f.read().splitlines())
    print("Core " + str(core) + ":  Searching Private Key..")
    iteration = 0
    while True:
        iteration += 1
        # Generate private + public keys and btc address
        private_key = sha256(mnemo.generate(strength=256))
        public_key = privtopub(private_key)
        btc_address = pubtoaddr(public_key)
        # Log rate
        if (iteration % log_rate_iterations) == 0:
            time_diff = dt.datetime.today().timestamp() - start_time
            print("Core :" + str(core) + " K/s = " + str(iteration / time_diff))
        # Write private + public key + address if it exists in the file
        if btc_address in publist:
            found_key = f"\nPublic: {str(public_key)} | Private: {str(private_key)} | Address: {str(btc_address)}\n"
            print(found_key)
            with open(found_keys, "a") as f:
                f.write(found_key)
            break


if __name__ == "__main__":
    jobs = []
    for core in range(cores):
        process = multiprocessing.Process(target=seek, args=(core,))
        jobs.append(process)
        process.start()
