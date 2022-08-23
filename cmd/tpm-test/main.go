package main

import (
	"flag"
	"log"

	sal "github.com/shuvava/tpm/pkg/tpm"
)

var (
	ctxFile = flag.String("ctx", "key.ctx", "TPM key context")
	handle  = flag.Int("parent", 0, "key parent object ID")
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
)

func main() {
	flag.Parse()
	var key sal.TPM
	var err error
	if *handle > 0 {
		key, err = sal.NewTPMCrypto(&sal.TPM{
			TpmDevice: *tpmPath,
			TpmHandle: uint32(*handle),
		})
		if err != nil {
			log.Println(err)
			return
		}
	} else {
		key, err = sal.NewTPMCrypto(&sal.TPM{
			TpmDevice:     *tpmPath,
			TpmHandleFile: *ctxFile,
		})
		if err != nil {
			log.Println(err)
			return
		}
	}
	k := key.Public()
	if k != nil {
		log.Println("key loaded")
	} else {
		log.Println("error on key load")
	}
}
