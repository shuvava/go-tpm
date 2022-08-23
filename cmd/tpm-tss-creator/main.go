package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/shuvava/tpm/pkg/tpm"
)

var (
	pubFile = flag.String("pubFile", "key.pub", "TPM public key File")
	keyFile = flag.String("keyFile", "key.priv", "TPM KeyFile")
	parent  = flag.Int("parent", int(tpm2.HandleOwner), "key parent object ID")
)

func main() {
	flag.Parse()
	fmt.Fprintf(os.Stderr, "TSS parent objectID %X\n", *parent)
	var tss = tpm.TSS{Parent: tpmutil.Handle(uint32(*parent)), EmptyAuth: true}
	bpub, err := os.ReadFile(*pubFile)
	if err != nil {
		log.Println(err)
		return
	}
	bkey, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Println(err)
		return
	}
	tss.Public = bpub
	tss.Private = bkey
	b, err := tss.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "TSS marshaaling failed%v\n", err)
		os.Exit(1)
	}
	pemBlock := pem.Block{
		Type:  "TSS2 PRIVATE KEY",
		Bytes: b,
	}
	pemBytes := pem.EncodeToMemory(&pemBlock)
	err = os.WriteFile("key.tss", pemBytes, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ContextSave failed for ekh%v\n", err)
		os.Exit(1)
	}
	log.Println("file created")
}
