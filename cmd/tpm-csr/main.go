package main

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"crypto/x509"
	"crypto/x509/pkix"
	"flag"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
)

var (
	cfg = &certGenConfig{}
)

type certGenConfig struct {
	flCN       string
	flFileName string
	flSNI      string
}

var (
	tpmPath    = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	san        = flag.String("dnsSAN", "server.domain.com", "DNS SAN Value for cert")
	pemCSRFile = flag.String("pemCSRFile", "client.csr", "CSR File to write to")
	keyFile    = flag.String("keyFile", "client.bin", "TPM KeyFile")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}
	unrestrictedKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSAPSS,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func main() {

	flag.Parse()
	fmt.Fprintf(os.Stdout, "======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stdout, "can't open TPM %q: %v", tpmPath, err)
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Fprintf(os.Stdout, "%v\ncan't close TPM %q: %v", tpmPath, err)
			os.Exit(1)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			fmt.Fprintf(os.Stdout, "getting handles: %v", err)
			os.Exit(1)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				fmt.Fprintf(os.Stdout, "flushing handle 0x%x: %v", handle, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stdout, "Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	fmt.Fprintf(os.Stdout, "%d handles flushed\n", totalHandles)

	k, err := client.NewKey(rwc, tpm2.HandleOwner, unrestrictedKeyParams)
	if err != nil {
		fmt.Fprintf(os.Stdout, "can't create SRK %q: %v", tpmPath, err)
		os.Exit(1)
	}

	kh := k.Handle()
	fmt.Fprintf(os.Stdout, "======= ContextSave (k) ========")
	khBytes, err := tpm2.ContextSave(rwc, kh)
	if err != nil {
		fmt.Fprintf(os.Stdout, "ContextSave failed for ekh: %v", err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(*keyFile, khBytes, 0644)
	if err != nil {
		fmt.Fprintf(os.Stdout, "ContextSave failed for ekh: %v", err)
		os.Exit(1)
	}
	tpm2.FlushContext(rwc, kh)

	fmt.Fprintf(os.Stdout, "======= ContextLoad (k) ========")
	khBytes, err = ioutil.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stdout, "ContextLoad failed for ekh: %v", err)
		os.Exit(1)
	}
	kh, err = tpm2.ContextLoad(rwc, khBytes)
	if err != nil {
		fmt.Fprintf(os.Stdout, "ContextLoad failed for kh: %v", err)
		os.Exit(1)
	}
	kk, err := client.NewCachedKey(rwc, tpm2.HandleOwner, unrestrictedKeyParams, kh)
	s, err := kk.GetSigner()
	if err != nil {
		fmt.Fprintf(os.Stdout, "can't getSigner %q: %v", tpmPath, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "Parent handle %X\n", tpm2.HandleOwner)
	fmt.Fprintf(os.Stdout, "Key handle %X\n", kh)

	fmt.Fprintf(os.Stdout, "Creating CSR")

	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         *san,
		},
		DNSNames:           []string{*san},
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, s)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Failed to create CSR: %s", err)
		os.Exit(1)
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		},
	)
	fmt.Fprintf(os.Stdout, "CSR \b%s\n", string(pemdata))

	err = ioutil.WriteFile(*pemCSRFile, pemdata, 0644)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Could not write file %v", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "CSR written to: %s\n", *pemCSRFile)

}
