package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	sal "github.com/shuvava/tpm/pkg/tpm"
)

var (
	cacert  = flag.String("cacert", "ca.crt", "RootCA")
	address = flag.String("address", "", "Address of server")
	pubCert = flag.String("pubCert", "client.crt", "Public Cert file")
	keyFile = flag.String("tpmfile", "client.bin", "TPM KeyFile")
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
)

func main() {
	flag.Parse()

	caCert, err := os.ReadFile(*cacert)
	if err != nil {
		log.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	// clientCerts, err := tls.LoadX509KeyPair(
	// 	"certs/client.crt",
	// 	"certs/client.key",
	// )
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }

	r, err := sal.NewTPMCrypto(&sal.TPM{
		TpmDevice:          *tpmPath,
		TpmHandleFile:      *keyFile,
		PublicCertFile:     *pubCert,
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // required for go 1.15+ TLS
		ExtTLSConfig: &tls.Config{
			ServerName: "server.domain.com",
			RootCAs:    caCertPool,
			ClientCAs:  caCertPool,
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	tr := &http.Transport{
		// TLSClientConfig: &tls.Config{
		// 	RootCAs:      caCertPool,
		// 	ServerName:   "server.domain.com",
		// 	Certificates: []tls.Certificate{clientCerts},
		// },
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
