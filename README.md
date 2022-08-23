# TPM TSS

## TPM TSS Creator usage

`tpm-tss-creator` generates `TSS2 PRIVATE KEY` file from tpm2_tools output

```shell
# generate private key
tee "cert.config" > /dev/null <<EOT
[ req ]
default_bits = 4096
default_md = sha256
prompt = no
encrypt_key = no
distinguished_name = dn
[ dn ]
C = CA
O = Company
CN = device-011
OU = KeyTypeTPM
EOT
openssl req -new -newkey rsa:2048 -nodes  -config cert.config -keyout private.pem -new -out client.csr
# generate primary  key and upload cert into TPM
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.priv
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
# get parent cert object Id 
tpm2_evictcontrol -c primary.ctx
# >> persistent-handle: 0x81000006
# >> action: persisted

# remove/add with the same ID
# tpm2_evictcontrol -C o -c 0x81010002
# tpm2_evictcontrol -C o -c primary.ctx 0x81010002

# build TSS2 output
tpm-tss-creator -parent 0x81000006
# verification
openssl req -keyform engine -engine libtpm2tss -config cert.config -key key.tss -new -out key.csr
```

## TPM-client

Example of usage http.Client with TPM

## TPM-CSR

Example of CSR generation 

## TPM-Test

`tpm-test` utility verifying ability to load TMP certificate

## Links

* [sign_with_rsa](https://github.com/salrashid123/tpm2/blob/master/sign_with_rsa/main.go)
* [sign_verify_tpm](https://github.com/salrashid123/signer/blob/master/example/sign_verify_tpm/main.go)
* [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)
* [tpm2-tools docs](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_load.1/)
* [go-tpm-tools](https://github.com/google/go-tpm-tools/)
* [tpm2-asn-packer](https://github.com/rpofuk/tpm2-asn-packer/blob/master/lib/init.js)
* [TCG TSS 2](https://trustedcomputinggroup.org/wp-content/uploads/TSS_Overview_Common_Structures_Version-0.9_Revision-03_Review_030918.pdf)
* [private_key_test](https://github.com/paulgriffiths/pgtpm/blob/master/private_key_test.go)
* https://blog.salrashid.dev/articles/2019/tpm2_evp_sign_decrypt/
* https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md
* https://blog.fearcat.in/a?ID=01750-cc18b686-a5b8-43ba-8743-c30c6ba04618
* https://github.com/tpm2-software/tpm2-tools/issues/2691
* https://man.archlinux.org/man/tpm2_readpublic.1.en
