package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	sal "github.com/shuvava/tpm/pkg/tpm"
)

var (
	cacert    = flag.String("cacert", "ca.crt", "RootCA")
	address   = flag.String("address", "", "Address of server")
	pubCert   = flag.String("pubCert", "client.crt", "Public Cert file")
	keyFile   = flag.String("tpmfile", "", "TPM KeyFile")
	keyHandle = flag.Int("tpmHandle", 0, "TPM persistent key handle")
	tssFile   = flag.String("tpmfile", "", "TPM TSS 2.0 file generated by tpm2tss-genkey")
	tpmPath   = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
)

func main() {
	flag.Parse()

	u, err := url.Parse(*address)
	if err != nil {
		log.Println(err)
		return
	}

	caCert, err := os.ReadFile(*cacert)
	if err != nil {
		log.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	var tss *sal.TSS
	if tssFile != nil && *tssFile != "" {
		tss, err = sal.LoadFromFile(*tssFile)
		if err != nil {
			log.Println(err)
			return
		}
	}

	r, err := sal.NewTPMCrypto(&sal.TPM{
		Tss:           tss,
		TpmHandle:     uint32(*keyHandle),
		TpmHandleFile: *keyFile,

		TpmDevice:          *tpmPath,
		PublicCertFile:     *pubCert,
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // required for go 1.15+ TLS
		ExtTLSConfig: &tls.Config{
			ServerName: u.Hostname(),
			RootCAs:    caCertPool,
			ClientCAs:  caCertPool,
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	tr := &http.Transport{
		TLSClientConfig: r.TLSConfig(),
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("%s", *address))
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Println(string(htmlData))

}
