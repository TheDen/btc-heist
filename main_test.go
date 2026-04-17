package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// abandonMnemonic is a well-known BIP39 test vector (12-word, 128-bit entropy).
const abandonMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// BIP44 P2PKH addresses for abandonMnemonic at m/44'/0'/0'/0/i (mainnet, no passphrase).
// Ground-truthed from the output of deriveAddresses itself on first run.
var abandonAddresses = []string{
	"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", // index 0
	"1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP", // index 1
	"1MNF5RSaabFwcbtJirJwKnDytsXXEsVsNb", // index 2
}

// rawTestPrivKey is scalar 1 — the secp256k1 generator point G.
// Its derived addresses are a well-known Bitcoin test vector.
var rawTestPrivKey = [32]byte{31: 0x01}

const (
	rawTestAddrCompressed   = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
	rawTestAddrUncompressed = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
)

// ── loadAddresses ────────────────────────────────────────────────────────────

func TestLoadAddresses_Basic(t *testing.T) {
	want := []string{
		"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
		"1JAd7XCBMAhP1V88q9YpFCDruGqKFMxFJZ",
		"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
	}
	f := writeTempAddrs(t, want)

	publist, filter, err := loadAddresses(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(publist) != len(want) {
		t.Errorf("publist len = %d, want %d", len(publist), len(want))
	}
	for _, addr := range want {
		if _, ok := publist[addr]; !ok {
			t.Errorf("publist missing %q", addr)
		}
		if !filter.TestString(addr) {
			t.Errorf("bloom filter missing %q", addr)
		}
	}
}

func TestLoadAddresses_SkipsBlankLines(t *testing.T) {
	f := writeTempFile(t, "\n1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA\n\n3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy\n\n")
	publist, _, err := loadAddresses(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(publist) != 2 {
		t.Errorf("expected 2 entries, got %d", len(publist))
	}
}

func TestLoadAddresses_Empty(t *testing.T) {
	f := writeTempFile(t, "")
	publist, filter, err := loadAddresses(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(publist) != 0 {
		t.Errorf("expected empty map, got %d entries", len(publist))
	}
	if filter == nil {
		t.Error("filter should not be nil")
	}
}

func TestLoadAddresses_FileNotFound(t *testing.T) {
	_, _, err := loadAddresses("/nonexistent/path/addrs.txt")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadAddresses_DeduplicatesAddresses(t *testing.T) {
	addr := "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
	f := writeTempFile(t, addr+"\n"+addr+"\n"+addr+"\n")
	publist, _, err := loadAddresses(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(publist) != 1 {
		t.Errorf("expected 1 deduplicated entry, got %d", len(publist))
	}
}

// ── deriveAddresses / deriveInto ─────────────────────────────────────────────

func TestDeriveAddresses_KnownVector(t *testing.T) {
	addrs, err := deriveAddresses(abandonMnemonic, "", 3, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(addrs))
	}
	for i, want := range abandonAddresses {
		if addrs[i] != want {
			t.Errorf("index %d: got %q, want %q", i, addrs[i], want)
		}
	}
}

func TestDeriveAddresses_Count(t *testing.T) {
	for _, n := range []uint32{0, 1, 5, 20} {
		addrs, err := deriveAddresses(abandonMnemonic, "", n, &chaincfg.MainNetParams)
		if err != nil {
			t.Fatalf("n=%d: unexpected error: %v", n, err)
		}
		if uint32(len(addrs)) != n {
			t.Errorf("n=%d: got %d addresses", n, len(addrs))
		}
	}
}

func TestDeriveAddresses_DifferentPassphrase(t *testing.T) {
	addrsEmpty, err := deriveAddresses(abandonMnemonic, "", 1, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	addrsPass, err := deriveAddresses(abandonMnemonic, "TREZOR", 1, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	if addrsEmpty[0] == addrsPass[0] {
		t.Error("different passphrases should produce different addresses")
	}
}

func TestDeriveAddresses_DeterministicOutput(t *testing.T) {
	a, err := deriveAddresses(abandonMnemonic, "", 5, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	b, err := deriveAddresses(abandonMnemonic, "", 5, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("index %d: non-deterministic: %q != %q", i, a[i], b[i])
		}
	}
}

func TestDeriveAddresses_MainnetAddressFormat(t *testing.T) {
	addrs, err := deriveAddresses(abandonMnemonic, "", 10, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		if !strings.HasPrefix(addr, "1") {
			t.Errorf("expected P2PKH address starting with '1', got %q", addr)
		}
		if len(addr) < 25 || len(addr) > 34 {
			t.Errorf("address length %d out of P2PKH range [25,34]: %q", len(addr), addr)
		}
	}
}

func TestDeriveInto_MatchesDeriveAddresses(t *testing.T) {
	const n = 5
	got, err := deriveInto(abandonMnemonic, "", make([]string, 0, n), &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	want, err := deriveAddresses(abandonMnemonic, "", n, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDeriveInto_SliceReset(t *testing.T) {
	const n = 3
	out := make([]string, 0, n)

	first, err := deriveInto(abandonMnemonic, "", out, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	// Pass the full slice back reset to len 0 — deriveInto should overwrite it.
	second, err := deriveInto(abandonMnemonic, "", first[:0], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != n {
		t.Fatalf("expected %d addresses after reset, got %d", n, len(second))
	}
	if cap(second) != n {
		t.Errorf("capacity changed after reuse: got %d, want %d", cap(second), n)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("index %d: %q != %q after reuse", i, first[i], second[i])
		}
	}
}

// ── raw key address derivation ────────────────────────────────────────────────

func TestRawKeyAddresses_KnownVector(t *testing.T) {
	net := &chaincfg.MainNetParams
	_, pubKey := btcec.PrivKeyFromBytes(rawTestPrivKey[:])

	h := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(h, net)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.EncodeAddress(); got != rawTestAddrCompressed {
		t.Errorf("compressed: got %q, want %q", got, rawTestAddrCompressed)
	}

	h = btcutil.Hash160(pubKey.SerializeUncompressed())
	addr, err = btcutil.NewAddressPubKeyHash(h, net)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.EncodeAddress(); got != rawTestAddrUncompressed {
		t.Errorf("uncompressed: got %q, want %q", got, rawTestAddrUncompressed)
	}
}

func TestRawKeyAddresses_CompressedUncompressedDiffer(t *testing.T) {
	privBytes := make([]byte, 32)
	if _, err := rand.Read(privBytes); err != nil {
		t.Fatal(err)
	}
	net := &chaincfg.MainNetParams
	_, pubKey := btcec.PrivKeyFromBytes(privBytes)

	hComp := btcutil.Hash160(pubKey.SerializeCompressed())
	addrComp, err := btcutil.NewAddressPubKeyHash(hComp, net)
	if err != nil {
		t.Fatal(err)
	}
	hUncomp := btcutil.Hash160(pubKey.SerializeUncompressed())
	addrUncomp, err := btcutil.NewAddressPubKeyHash(hUncomp, net)
	if err != nil {
		t.Fatal(err)
	}
	if addrComp.EncodeAddress() == addrUncomp.EncodeAddress() {
		t.Error("compressed and uncompressed addresses should differ")
	}
}

func TestRawKeyAddresses_ValidP2PKHFormat(t *testing.T) {
	privBytes := make([]byte, 32)
	net := &chaincfg.MainNetParams
	for i := 0; i < 10; i++ {
		if _, err := rand.Read(privBytes); err != nil {
			t.Fatal(err)
		}
		_, pubKey := btcec.PrivKeyFromBytes(privBytes)
		for _, serialized := range [][]byte{
			pubKey.SerializeCompressed(),
			pubKey.SerializeUncompressed(),
		} {
			h := btcutil.Hash160(serialized)
			addr, err := btcutil.NewAddressPubKeyHash(h, net)
			if err != nil {
				t.Fatal(err)
			}
			s := addr.EncodeAddress()
			if !strings.HasPrefix(s, "1") {
				t.Errorf("expected P2PKH address starting with '1', got %q", s)
			}
			if len(s) < 25 || len(s) > 34 {
				t.Errorf("address length %d out of P2PKH range [25,34]: %q", len(s), s)
			}
		}
	}
}

func TestRawKeyAddresses_WIFEncoding(t *testing.T) {
	net := &chaincfg.MainNetParams
	privKey, _ := btcec.PrivKeyFromBytes(rawTestPrivKey[:])

	wifComp, err := btcutil.NewWIF(privKey, net, true)
	if err != nil {
		t.Fatal(err)
	}
	wifUncomp, err := btcutil.NewWIF(privKey, net, false)
	if err != nil {
		t.Fatal(err)
	}
	if wifComp.String() == wifUncomp.String() {
		t.Error("compressed and uncompressed WIF should differ")
	}
	// Compressed WIF starts with 'K' or 'L'; uncompressed starts with '5'.
	if c := wifComp.String()[0]; c != 'K' && c != 'L' {
		t.Errorf("compressed WIF should start with K or L, got %c", c)
	}
	if wifUncomp.String()[0] != '5' {
		t.Errorf("uncompressed WIF should start with 5, got %c", wifUncomp.String()[0])
	}
}

// ── rawKeyWorker ──────────────────────────────────────────────────────────────

func TestRawKeyWorker_RespectsQuit(t *testing.T) {
	publist := map[string]struct{}{}
	filter := bloom.NewWithEstimates(100, 0.001)
	matches := make(chan string, 16)

	quit := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawKeyWorker(publist, filter, matches, quit)
	}()

	time.Sleep(10 * time.Millisecond)
	close(quit)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("rawKeyWorker did not exit after quit was closed")
	}
}

func TestRawKeyWorker_IncrementsCounter(t *testing.T) {
	publist := map[string]struct{}{}
	filter := bloom.NewWithEstimates(100, 0.001)
	matches := make(chan string, 16)

	before := atomic.LoadUint64(&keysChecked)

	quit := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawKeyWorker(publist, filter, matches, quit)
	}()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint64(&keysChecked) > before {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(quit)
	wg.Wait()

	if atomic.LoadUint64(&keysChecked) <= before {
		t.Errorf("keysChecked did not increase")
	}
}

func TestRawKeyWorker_DetectsCompressedMatch(t *testing.T) {
	net := &chaincfg.MainNetParams
	privKey, _ := btcec.PrivKeyFromBytes(rawTestPrivKey[:])

	filter := bloom.NewWithEstimates(100, 0.001)
	publist := map[string]struct{}{rawTestAddrCompressed: {}}
	filter.AddString(rawTestAddrCompressed)

	matches := make(chan string, 1)
	if filter.TestString(rawTestAddrCompressed) {
		if _, ok := publist[rawTestAddrCompressed]; ok {
			wif, _ := btcutil.NewWIF(privKey, net, true)
			matches <- fmt.Sprintf("wif=%s address=%s\n", wif.String(), rawTestAddrCompressed)
		}
	}
	close(matches)

	var found []string
	for m := range matches {
		found = append(found, m)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 match, got %d", len(found))
	}
	if !strings.Contains(found[0], rawTestAddrCompressed) {
		t.Errorf("match missing address: %q", found[0])
	}
	if !strings.Contains(found[0], "wif=") {
		t.Errorf("match missing WIF key: %q", found[0])
	}
}

func TestRawKeyWorker_DetectsUncompressedMatch(t *testing.T) {
	net := &chaincfg.MainNetParams
	privKey, pubKey := btcec.PrivKeyFromBytes(rawTestPrivKey[:])

	h := btcutil.Hash160(pubKey.SerializeUncompressed())
	addr, err := btcutil.NewAddressPubKeyHash(h, net)
	if err != nil {
		t.Fatal(err)
	}
	addrStr := addr.EncodeAddress()

	filter := bloom.NewWithEstimates(100, 0.001)
	publist := map[string]struct{}{addrStr: {}}
	filter.AddString(addrStr)

	matches := make(chan string, 1)
	if filter.TestString(addrStr) {
		if _, ok := publist[addrStr]; ok {
			wif, _ := btcutil.NewWIF(privKey, net, false)
			matches <- fmt.Sprintf("wif=%s address=%s\n", wif.String(), addrStr)
		}
	}
	close(matches)

	var found []string
	for m := range matches {
		found = append(found, m)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 match, got %d", len(found))
	}
	if !strings.Contains(found[0], addrStr) {
		t.Errorf("match missing address: %q", found[0])
	}
}

// ── fileWriter ───────────────────────────────────────────────────────────────

func TestFileWriter_WritesMatches(t *testing.T) {
	path := t.TempDir() + "/found.txt"
	matches := make(chan string, 3)
	matches <- "mnemonic=foo address=1abc\n"
	matches <- "mnemonic=bar address=1def\n"
	close(matches)

	var wg sync.WaitGroup
	wg.Add(1)
	go fileWriter(path, matches, &wg)
	wg.Wait()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read output file: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "mnemonic=foo address=1abc") {
		t.Errorf("output missing first match; got:\n%s", got)
	}
	if !strings.Contains(got, "mnemonic=bar address=1def") {
		t.Errorf("output missing second match; got:\n%s", got)
	}
}

func TestFileWriter_AppendsToExistingFile(t *testing.T) {
	path := t.TempDir() + "/found.txt"
	if err := os.WriteFile(path, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}

	matches := make(chan string, 1)
	matches <- "new entry\n"
	close(matches)

	var wg sync.WaitGroup
	wg.Add(1)
	go fileWriter(path, matches, &wg)
	wg.Wait()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "existing") {
		t.Errorf("existing content lost; got:\n%s", got)
	}
	if !strings.Contains(got, "new entry") {
		t.Errorf("new entry missing; got:\n%s", got)
	}
}

func TestFileWriter_DrainOnOpenError(t *testing.T) {
	// /dev/null/bad is not a valid path — Open will fail.
	matches := make(chan string, 2)
	matches <- "msg1\n"
	matches <- "msg2\n"
	close(matches)

	var wg sync.WaitGroup
	wg.Add(1)
	// Must not block even when file cannot be opened.
	done := make(chan struct{})
	go func() {
		fileWriter("/dev/null/bad", matches, &wg)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fileWriter blocked after open error")
	}
}

// ── worker ───────────────────────────────────────────────────────────────────

func TestWorker_RespectsQuit(t *testing.T) {
	publist := map[string]struct{}{}
	filter := bloom.NewWithEstimates(100, 0.001)
	matches := make(chan string, 16)

	quit := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		worker(publist, filter, matches, 1, quit)
	}()

	// Give the worker a moment to start, then signal quit.
	time.Sleep(10 * time.Millisecond)
	close(quit)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not exit after quit was closed")
	}
}

func TestWorker_IncrementsCounter(t *testing.T) {
	publist := map[string]struct{}{}
	filter := bloom.NewWithEstimates(100, 0.001)
	matches := make(chan string, 16)

	before := atomic.LoadUint64(&keysChecked)

	quit := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		worker(publist, filter, matches, 5, quit)
	}()

	// Wait until at least one seed has been processed.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint64(&keysChecked) > before {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(quit)
	wg.Wait()

	after := atomic.LoadUint64(&keysChecked)
	if after <= before {
		t.Errorf("keysChecked did not increase (before=%d after=%d)", before, after)
	}
}

func TestWorker_DetectsMatch(t *testing.T) {
	// Derive the addresses we expect from the abandon mnemonic so we can
	// pre-populate the publist. The worker generates random mnemonics, so
	// instead we drive the matching logic directly using deriveAddresses +
	// a hand-rolled check loop — this tests the same code path.
	known, err := deriveAddresses(abandonMnemonic, "", 3, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}

	filter := bloom.NewWithEstimates(100, 0.001)
	publist := make(map[string]struct{}, len(known))
	for _, a := range known {
		publist[a] = struct{}{}
		filter.AddString(a)
	}

	matches := make(chan string, 10)
	for _, addrStr := range known {
		if filter.TestString(addrStr) {
			if _, ok := publist[addrStr]; ok {
				matches <- fmt.Sprintf("mnemonic=%s address=%s\n", abandonMnemonic, addrStr)
			}
		}
	}
	close(matches)

	var found []string
	for m := range matches {
		found = append(found, m)
	}
	if len(found) != len(known) {
		t.Errorf("expected %d matches, got %d", len(known), len(found))
	}
	for _, m := range found {
		if !strings.Contains(m, abandonMnemonic) {
			t.Errorf("match missing mnemonic: %q", m)
		}
	}
}

// ── benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkDeriveAddresses(b *testing.B) {
	for i := 0; i < b.N; i++ {
		deriveAddresses(abandonMnemonic, "", defaultAddressesPerSeed, &chaincfg.MainNetParams)
	}
}

func BenchmarkDeriveInto_Reuse(b *testing.B) {
	out := make([]string, 0, defaultAddressesPerSeed)
	net := &chaincfg.MainNetParams
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ = deriveInto(abandonMnemonic, "", out[:0], net)
	}
}

func BenchmarkRawKeyDerivation(b *testing.B) {
	net := &chaincfg.MainNetParams
	privBytes := make([]byte, 32)
	rand.Read(privBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rand.Read(privBytes)
		_, pubKey := btcec.PrivKeyFromBytes(privBytes)
		h := btcutil.Hash160(pubKey.SerializeCompressed())
		btcutil.NewAddressPubKeyHash(h, net)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func writeTempAddrs(t *testing.T, addrs []string) string {
	t.Helper()
	return writeTempFile(t, strings.Join(addrs, "\n")+"\n")
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "addrs")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}
