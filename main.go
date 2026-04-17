package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/exp/mmap"
)

// addrHash stores the raw 20-byte Hash160 of a public key, used as a compact
// map/bloom key that eliminates base58 encoding from the hot path.
type addrHash [20]byte

const (
	// bloomEstimate is sized above the ~50M addresses in the loyce.club dataset.
	bloomEstimate = 100_000_000
	bloomFPRate   = 0.0001 // 0.01% false positive rate

	logInterval  = 5 * time.Second
	matchChanBuf = 64

	// defaultAddressesPerSeed amortises the expensive PBKDF2 seed derivation
	// across multiple child addresses. Each extra derive is cheap (HMAC-SHA512
	// + point addition) compared to the 2048-round PBKDF2 in NewSeed.
	defaultAddressesPerSeed = 50

	// counterFlushInterval is how many address checks a worker accumulates
	// locally before flushing to the shared atomics, reducing contention.
	counterFlushInterval = 1_000
)

var (
	keysChecked uint64
	keysMatched uint64
)

// newFastRNG returns a ChaCha8 CSPRNG seeded from crypto/rand.
// Much faster than crypto/rand for bulk random byte generation since it
// avoids per-call syscall overhead.
func newFastRNG() *mrand.ChaCha8 {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic(err)
	}
	return mrand.NewChaCha8(seed)
}

// loadAddresses memory-maps filename and populates a map and Bloom filter
// keyed on the raw 20-byte Hash160 extracted from each address. Using binary
// keys avoids base58 encoding in the hot path and reduces bloom hash input size.
func loadAddresses(filename string) (map[addrHash]struct{}, *bloom.BloomFilter, error) {
	r, err := mmap.Open(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", filename, err)
	}
	defer r.Close()

	sr := io.NewSectionReader(r, 0, int64(r.Len()))
	scanner := bufio.NewScanner(sr)
	// 4 MB read buffer — reduces the number of Read calls over the large file.
	scanner.Buffer(make([]byte, 4*1024*1024), bufio.MaxScanTokenSize)

	net := &chaincfg.MainNetParams
	filter := bloom.NewWithEstimates(bloomEstimate, bloomFPRate)
	// Pre-allocate near the expected dataset size to avoid repeated rehashing.
	publist := make(map[addrHash]struct{}, bloomEstimate)

	var skipped int
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		decoded, err := btcutil.DecodeAddress(line, net)
		if err != nil {
			skipped++
			continue
		}
		sa := decoded.ScriptAddress()
		if len(sa) != 20 {
			skipped++
			continue
		}
		var h addrHash
		copy(h[:], sa)
		publist[h] = struct{}{}
		filter.Add(h[:])
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan %s: %w", filename, err)
	}
	if skipped > 0 {
		fmt.Printf("Skipped %d addresses that could not be decoded.\n", skipped)
	}
	return publist, filter, nil
}

// deriveHashesInto fills out (reset to len 0, capacity unchanged) with
// cap(out) Hash160 values on the BIP44 external chain (m/44'/0'/0'/0/i)
// for the given mnemonic and passphrase. Returns raw hashes instead of
// base58-encoded strings to avoid encoding overhead in the hot path.
// Reusing the backing array across calls avoids a heap allocation per seed.
//
// Cost breakdown per call:
//  1. bip39.NewSeed  — PBKDF2 (2048 × HMAC-SHA512): the dominant cost, ~1–5 ms
//  2. NewMaster + 4 hardened Derives for m/44'/0'/0'/0
//  3. n non-hardened child Derives + Hash160 (~0.05 ms each)
func deriveHashesInto(mnemonic, passphrase string, out []addrHash, net *chaincfg.Params) ([]addrHash, error) {
	seed := bip39.NewSeed(mnemonic, passphrase)

	masterKey, err := hdkeychain.NewMaster(seed, net)
	if err != nil {
		return nil, err
	}
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 44)
	if err != nil {
		return nil, err
	}
	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, err
	}
	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, err
	}
	external, err := account.Derive(0)
	if err != nil {
		return nil, err
	}

	n := uint32(cap(out))
	out = out[:0]
	for i := uint32(0); i < n; i++ {
		child, err := external.Derive(i)
		if err != nil {
			return out, err
		}
		pub, err := child.ECPubKey()
		if err != nil {
			return out, err
		}
		h := btcutil.Hash160(pub.SerializeCompressed())
		var hash addrHash
		copy(hash[:], h)
		out = append(out, hash)
	}
	return out, nil
}

// deriveAddresses is a convenience wrapper around deriveHashesInto that returns
// base58-encoded P2PKH address strings. Used by tests and one-off callers.
func deriveAddresses(mnemonic, passphrase string, n uint32, net *chaincfg.Params) ([]string, error) {
	hashes, err := deriveHashesInto(mnemonic, passphrase, make([]addrHash, 0, n), net)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, len(hashes))
	for i, h := range hashes {
		addr, err := btcutil.NewAddressPubKeyHash(h[:], net)
		if err != nil {
			return nil, err
		}
		addrs[i] = addr.EncodeAddress()
	}
	return addrs, nil
}

// worker continuously generates BIP39 mnemonics, derives BIP44 addresses, and
// checks them against the Bloom filter and address map. Each goroutine is
// independent — no locks in the hot path.
//
// Uses a ChaCha8 CSPRNG for fast entropy generation (avoids crypto/rand syscalls)
// and raw Hash160 lookups (avoids base58 encoding per address).
func worker(
	publist map[addrHash]struct{},
	filter *bloom.BloomFilter,
	matches chan<- string,
	numAddresses uint32,
	quit <-chan struct{},
) {
	net := &chaincfg.MainNetParams
	rng := newFastRNG()
	entropy := make([]byte, 16) // 128-bit entropy for 12-word BIP39 mnemonic

	// Pre-allocate once; deriveHashesInto reuses the backing array every iteration.
	addrs := make([]addrHash, 0, numAddresses)

	var localChecked, localMatched uint64
	defer func() {
		atomic.AddUint64(&keysChecked, localChecked)
		atomic.AddUint64(&keysMatched, localMatched)
	}()

	for {
		select {
		case <-quit:
			return
		default:
		}

		rng.Read(entropy)
		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			continue
		}

		addrs, err = deriveHashesInto(mnemonic, "", addrs, net)
		if err != nil {
			continue
		}

		for _, h := range addrs {
			localChecked++
			// Two-stage lookup: cheap Bloom filter first, then exact map check.
			if filter.Test(h[:]) {
				if _, ok := publist[h]; ok {
					localMatched++
					// Only encode the address to base58 on match (astronomically rare).
					addr, _ := btcutil.NewAddressPubKeyHash(h[:], net)
					matches <- fmt.Sprintf("mnemonic=%s address=%s\n", mnemonic, addr.EncodeAddress())
				}
			}
		}

		if localChecked >= counterFlushInterval {
			atomic.AddUint64(&keysChecked, localChecked)
			atomic.AddUint64(&keysMatched, localMatched)
			localChecked, localMatched = 0, 0
		}
	}
}

// rawKeyWorker generates random 32-byte private keys and checks the resulting
// P2PKH addresses against the address set. Both the compressed and uncompressed
// public key forms are checked because pre-HD wallets (pre-2013) commonly used
// uncompressed keys, which produce a different address from the same private key.
// Matches are reported in WIF format so the key can be imported directly into a
// wallet.
//
// Uses a ChaCha8 CSPRNG for fast key generation and raw Hash160 lookups.
// WIF and base58 encoding are deferred to match time only.
func rawKeyWorker(
	publist map[addrHash]struct{},
	filter *bloom.BloomFilter,
	matches chan<- string,
	quit <-chan struct{},
) {
	net := &chaincfg.MainNetParams
	rng := newFastRNG()

	var localChecked, localMatched uint64
	defer func() {
		atomic.AddUint64(&keysChecked, localChecked)
		atomic.AddUint64(&keysMatched, localMatched)
	}()

	privBytes := make([]byte, 32)

	for {
		select {
		case <-quit:
			return
		default:
		}

		rng.Read(privBytes)
		privKey, pubKey := btcec.PrivKeyFromBytes(privBytes)

		// Compressed address (most common post-2013).
		hComp := btcutil.Hash160(pubKey.SerializeCompressed())
		var hashComp addrHash
		copy(hashComp[:], hComp)
		localChecked++
		if filter.Test(hashComp[:]) {
			if _, ok := publist[hashComp]; ok {
				localMatched++
				wif, _ := btcutil.NewWIF(privKey, net, true)
				addr, _ := btcutil.NewAddressPubKeyHash(hashComp[:], net)
				matches <- fmt.Sprintf("wif=%s address=%s\n", wif.String(), addr.EncodeAddress())
			}
		}

		// Uncompressed address (pre-HD / early wallets).
		hUncomp := btcutil.Hash160(pubKey.SerializeUncompressed())
		var hashUncomp addrHash
		copy(hashUncomp[:], hUncomp)
		localChecked++
		if filter.Test(hashUncomp[:]) {
			if _, ok := publist[hashUncomp]; ok {
				localMatched++
				wif, _ := btcutil.NewWIF(privKey, net, false)
				addr, _ := btcutil.NewAddressPubKeyHash(hashUncomp[:], net)
				matches <- fmt.Sprintf("wif=%s address=%s\n", wif.String(), addr.EncodeAddress())
			}
		}

		if localChecked >= counterFlushInterval {
			atomic.AddUint64(&keysChecked, localChecked)
			atomic.AddUint64(&keysMatched, localMatched)
			localChecked, localMatched = 0, 0
		}
	}
}

// fileWriter receives match strings from workers and appends them to keyfile.
// It also echoes each match to stdout. Running in a dedicated goroutine keeps
// all file I/O off the hot path.
func fileWriter(keyfile string, matches <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	f, err := os.OpenFile(keyfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open output file: %v\n", err)
		for range matches { // drain so workers never block
		}
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for msg := range matches {
		_, _ = fmt.Fprint(w, msg)
		_ = w.Flush()
		fmt.Print(msg)
	}
}

// statsLogger prints throughput and totals every logInterval.
func statsLogger(quit <-chan struct{}) {
	ticker := time.NewTicker(logInterval)
	defer ticker.Stop()

	start := time.Now()
	prevCount := uint64(0)
	prevTime := start

	for {
		select {
		case <-quit:
			return
		case t := <-ticker.C:
			current := atomic.LoadUint64(&keysChecked)
			matched := atomic.LoadUint64(&keysMatched)
			rate := float64(current-prevCount) / t.Sub(prevTime).Seconds()
			fmt.Printf("[%s] %.0f keys/s  total: %d  matched: %d\n",
				t.Sub(start).Round(time.Second), rate, current, matched)
			prevCount = current
			prevTime = t
		}
	}
}

func main() {
	cores := flag.Int("c", runtime.NumCPU(), "number of CPU cores to use")
	addressFile := flag.String("f", "Bitcoin_addresses_LATEST.txt", "file containing BTC addresses")
	keyfile := flag.String("o", "found_keys.txt", "output file for found keys")
	numAddresses := flag.Uint("n", defaultAddressesPerSeed, "addresses to check per mnemonic (amortises PBKDF2 cost)")
	flag.Parse()

	fmt.Printf("Loading %q...\n", *addressFile)
	publist, filter, err := loadAddresses(*addressFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d addresses.\n", len(publist))

	quit := make(chan struct{})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nShutting down…")
		close(quit)
	}()

	matches := make(chan string, matchChanBuf)

	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go fileWriter(*keyfile, matches, &writerWg)

	go statsLogger(quit)

	fmt.Printf("Starting %d workers, %d addresses per mnemonic.\n", *cores, *numAddresses)

	var workerWg sync.WaitGroup
	for i := 0; i < *cores; i++ {
		workerWg.Add(2)
		go func() {
			defer workerWg.Done()
			worker(publist, filter, matches, uint32(*numAddresses), quit)
		}()
		go func() {
			defer workerWg.Done()
			rawKeyWorker(publist, filter, matches, quit)
		}()
	}

	workerWg.Wait()
	close(matches)
	writerWg.Wait()

	fmt.Printf("Done. Checked %d keys, matched %d.\n",
		atomic.LoadUint64(&keysChecked),
		atomic.LoadUint64(&keysMatched))
}
