package tpm

import (
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpmutil"
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
