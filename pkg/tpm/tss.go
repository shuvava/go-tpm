package tpm

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const defaultPassword = ""

var (
	pcrSelection = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{}}

	defaultPrimaryRSATemplate = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagNoDA | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			Sign: &tpm2.SigScheme{
				Alg: tpm2.AlgNull,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
			ModulusRaw:  make([]byte, 256),
		},
	}

	defaultPrimaryECCTemplate = tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagNoDA | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: nil,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
			KDF: &tpm2.KDFScheme{
				Alg: tpm2.AlgNull,
			},
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
		},
	}
)

// TSS OpenSSL TMP access key format
type TSS struct {
	Type      string
	EmptyAuth bool
	Parent    tpmutil.Handle
	Public    []byte
	Private   []byte
}

func toHexStr(a []byte, sep string) string {
	s := make([]string, len(a))
	for i, b := range a {
		s[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(s, sep)
}

func (msg *TSS) Unmarshal(b []byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return
	}
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
		return nil, asn1.StructuralError{Msg: fmt.Sprintf(
			"Invalid messageV1 object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, toHexStr(b, " "))}
	}
	next := raw.Bytes
	var obj asn1.ObjectIdentifier
	next, err = asn1.Unmarshal(next, &obj)
	if err != nil {
		return
	}
	var exProps asn1.RawValue
	next, err = asn1.Unmarshal(next, &exProps)
	if err != nil {
		return
	}
	var auth asn1.Flag
	_, err = asn1.Unmarshal(exProps.Bytes, &auth)
	if err != nil {
		return
	}
	var parent int32
	next, err = asn1.Unmarshal(next, &parent)
	if err != nil {
		return
	}
	var pubKey []byte
	next, err = asn1.Unmarshal(next, &pubKey)
	if err != nil {
		return
	}
	var privKey []byte
	_, err = asn1.Unmarshal(next, &privKey)
	if err != nil {
		return
	}
	msg.Type = obj.String()
	msg.EmptyAuth = bool(auth)
	msg.Parent = tpmutil.Handle(parent)
	msg.Public = pubKey
	msg.Private = privKey
	return
}

func (msg *TSS) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true}
	obj := asn1.ObjectIdentifier([]int{2, 23, 133, 10, 1, 3})
	buf, err = asn1.Marshal(obj)
	if err != nil {
		return
	}
	raw.Bytes = buf

	exProps := asn1.RawValue{Class: asn1.ClassContextSpecific, IsCompound: true}
	exProps.Bytes = []byte{1, 1, 1}
	buf, err = asn1.Marshal(exProps)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = asn1.Marshal(int32(msg.Parent))
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = asn1.Marshal(msg.Public)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = asn1.Marshal(msg.Private)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	return asn1.Marshal(raw)
}

func decode(p []byte) ([]byte, error) {
	a := make([]byte, len(p))
	copy(a, p)
	tpmPubBlob := tpmutil.U16Bytes(a)
	bufTest := bytes.NewBuffer(tpmPubBlob)
	err := tpmPubBlob.TPMUnmarshal(bufTest)
	if err != nil {
		return nil, fmt.Errorf("decoding error: %v", err)
	}
	return tpmPubBlob, nil
}

// DecodePublic converts byte array into tpm2.Public structure
func (msg *TSS) DecodePublic() (*tpm2.Public, error) {
	tpmPubBlob, err := decode(msg.Public)
	if err != nil {
		return nil, err
	}
	pub, err := tpm2.DecodePublic(tpmPubBlob)

	return &pub, err
}

func (msg *TSS) loadPrimary(rw io.ReadWriter) (tpmutil.Handle, error) {
	if msg.Parent != 0 && msg.Parent != tpm2.HandleOwner {
		key, err := client.NewCachedKey(rw, tpm2.HandleOwner, defaultPrimaryECCTemplate, msg.Parent)
		if err != nil {
			return 0, err
		}
		return key.Handle(), nil
	}
	pkh, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, pcrSelection, defaultPassword, defaultPassword, defaultPrimaryECCTemplate)
	if err != nil {
		return 0, fmt.Errorf("error on creating primary key: %v", err)
	}
	return pkh, nil
}

// LoadKey load TSS 2.0 key into transient TPM memory
// caller should execute tpm2.FlushContext for returned handle
func (msg *TSS) LoadKey(rw io.ReadWriter) (tpmutil.Handle, error) {
	publicBlob, err := decode(msg.Public)
	if err != nil {
		return 0, err
	}
	privateBlob, err := decode(msg.Private)
	if err != nil {
		return 0, err
	}
	primaryHandle, err := msg.loadPrimary(rw)
	if err != nil {
		return 0, err
	}
	defer func(rw io.ReadWriter, handle tpmutil.Handle) {
		_ = tpm2.FlushContext(rw, primaryHandle)
	}(rw, primaryHandle)
	keyHandle, _, err := tpm2.Load(rw, primaryHandle, "", publicBlob, privateBlob)
	if err != nil {
		return 0, fmt.Errorf("load key error: %v\n", err)
	}
	return keyHandle, nil
}

// LoadFromFile loads TSS2 pem encoded file into TSS struct
func LoadFromFile(f string) (*TSS, error) {
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block.Type != "TSS2 PRIVATE KEY" {
		return nil, fmt.Errorf("failed to find corrent block type")
	}
	msg := &TSS{}
	rest, err := msg.Unmarshal(block.Bytes)
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected block size")
	}
	return msg, nil
}
