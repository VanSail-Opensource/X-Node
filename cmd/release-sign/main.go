// release-sign is a build-time helper, not an installed agent binary.
package main

import (
	"aead.dev/minisign"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	generate := flag.Bool("generate-key", false, "generate a private key outside the checkout")
	keyPath := flag.String("key-file", "", "private key file")
	publicPath := flag.String("public-out", "", "public key output")
	manifest := flag.String("manifest", "", "SHA256SUMS path")
	version := flag.String("version", "", "signed release version")
	flag.Parse()
	if *keyPath == "" {
		fail("key-file is required")
	}
	if *generate {
		if _, e := os.Stat(*keyPath); e == nil {
			fail("private key already exists")
		}
		public, private, e := minisign.GenerateKey(nil)
		if e != nil {
			fail(e.Error())
		}
		secret, _ := private.MarshalText()
		pub, _ := public.MarshalText()
		if e = os.MkdirAll(filepath.Dir(*keyPath), 0700); e != nil {
			fail(e.Error())
		}
		if e = os.WriteFile(*keyPath, secret, 0600); e != nil {
			fail(e.Error())
		}
		if *publicPath == "" {
			fail("public-out is required")
		}
		if e = os.WriteFile(*publicPath, pub, 0644); e != nil {
			fail(e.Error())
		}
		fmt.Println("Release key generated; private material was not printed.")
		return
	}
	b, e := os.ReadFile(*keyPath)
	if e != nil {
		fail("cannot read signing key")
	}
	var private minisign.PrivateKey
	if e = private.UnmarshalText(b); e != nil {
		fail("invalid signing key")
	}
	data, e := os.ReadFile(*manifest)
	if e != nil {
		fail("cannot read manifest")
	}
	reader := minisign.NewReader(bytes.NewReader(data))
	_, _ = io.Copy(io.Discard, reader)
	signature := reader.SignWithComments(private, "version:"+*version, "X-Node release")
	if e = os.WriteFile(*manifest+".minisig", signature, 0644); e != nil {
		fail(e.Error())
	}
}
func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
