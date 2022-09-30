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

## TPM 2.0 Protected Storage

When a Protected Object is in the TPM, it is in a Shielded Location because the only access to the
context of the object is with a Protected Capability (a TPM command). The size of TPM memory may be
limited and if the only storage for Protected Objects were the TPM Shielded Locations, the TPM’s
usefulness would be reduced. The effective memory of the TPM is expanded by using cryptographic
methods for Protected Objects when they are not in Shielded Locations.

### Symmetric Encryption

A symmetric key is used to encrypt the sensitive area of an object that was created by TPM2_Create() or
imported by TPM2_Import(). The symmetric key is derived from a seed value
contained in the Storage Parent’s sensitive area and the Name of the protected object.

### Protected Storage Hierarchy

The TPM supports the creation of hierarchies of Protected Locations. A hierarchy is constructed with
Storage Keys as the connectors to which other types of objects (keys, data, and other connectors) may
be attached.
The hierarchical relationship of objects allows segregation of objects based on the system-operating
environment (established by PCR or authorizations) as well as simplifying the management of groups of
related objects.

#### Hierarchical Relationship between Objects

A hierarchy is rooted in a secret seed key, kept in the TPM. To create a hierarchy of keys, the seed key
(Primary Seed) is used to generate a key that uses a specific set of algorithms. If this key is a restricted
decryption key, then it is a Parent Key. If it is not a Derivation Parent, then it is a Storage Parent under
which other objects may be created or attached.
A Storage Parent provides protection for the sensitive area in another object (a child) when that object is
stored outside of the TPM. Protection is provided by symmetric encryption and HMAC-based integrity
protection of the sensitive area. There are two different cases for sensitive area encryption: storage and
duplication.
When an Ordinary Object is created (TPM2_Create() or TPM2_CreateLoaded()) the keys used for
protection of the Object’s sensitive area are derived from a seed value (seedValue) in the sensitive area
of the Storage Key. When an Object is prepared for duplication, its sensitive area is protected by a
random key and a form of Diffie-Hellman is used to convey the key to the duplication target.

The objects in a hierarchy have a parent-child relationship. A Storage Key that is protecting other objects
is a Storage Parent and the objects that it is protecting are its children. The ancestors of an object are the
parent keys that connect the object to a TPM Primary Seed. Descendants of a key are all the objects that
have that Parent as an ancestor. Unless it is intended to be used as a parent, a child object may be of
any type

#### Duplication

Duplication is the process of allowing an object to be a child of additional Storage Parent keys. The new
parent (NP) may be in a hierarchy of the same TPM or of a different TPM.
Duplication occurs on a loaded object and produces a new, sensitive structure that is encrypted using the
methods of the NP. This new sensitive structure may not be used until TPM2_Import() has been executed
to convert the object from "external" to "internal" protections.

#### Primary Seed Hierarchies

A Primary Object is an object that is derived from a Primary Seed value. The sensitive area of a Primary
Object is not stored off of the TPM. The Primary Object will need to be regenerated each time it is needed
or it can be made persistent in NV memory on the TPM (TPM2_EvictControl()).
Once created, a Primary Object may be context-saved/restored

The consistency of the hierarchy settings is checked in object templates (TPM2_Create() and
TPM2_CreatePrimary()) and in public areas for loaded objects (TPM2_Load()) or duplicated objects
(TPM2_Import()).


### Object Creation

TPM2_Create(), TPM2_CreatePrimary() and TPM2_CreateLoaded() are used to create the objects (keys
and data) that are part of a TPM’s Storage hierarchy. TPM2_CreatePrimary() is used to create Primary
Objects that are derived from a Primary Seed. TPM2_Create() is used to create Ordinary Objects that are
generated with values from the TPM RNG. TPM2_CreateLoaded() can be used to create a Primary or
Ordinary Object.

In particular, when creating keys:
* TPM2_CreatePrimary() – creates and loads Primary Objects for immediate use, and provides
creationData.
* TPM2_Create() – creates Ordinary Objects for later use (via TPM2_Load()). TPM2_Create() returns a
BLOB containing the sensitive area of an Ordinary Object and provides creationData.
* TPM2_CreateLoaded()– depending on the type of the parent, generates and loads a Primary Object,
an Ordinary Object; or Derived Object.

### Object Loading

An object is either a key or data that can be loaded into the TPM for use. An object must be loaded before
the TPM can use or modify the object. Loading may require that the USER role authorization for the
Storage Parent be provided

It is possible to load just the public portion of an object into the TPM (TPM2_LoadExternal()) or to load
both the public and private portions (TPM2_Load()). If the sensitive area is to be manipulated or used,
then both portions are required to be loaded

### Context Management

To allow the TPM to be shared among many applications, the TPM supports context management. The
objects, sequence objects, and sessions used by an application may be loaded into the TPM when
needed and saved when a different application is using the TPM. The TPM Resource Manager (TRM) is
responsible for swapping the contexts so that the necessary resources are present in the TPM when
needed.
There are two types of contexts: those associated with Transient Objects, and those associated with
authorization sessions.
The four commands used to manage the contexts are
1. TPM2_ContextSave() – the TPM integrity protects, encrypts, and returns the context associated with
   a handle, 
2. TPM2_ContextLoad() – allows a previously saved context to be loaded to TPM RAM and have a
   handle assigned, 
3. TPM2_FlushContext() – the context information associated with the specified handle is erased from
   TPM RAM, and 
4. TPM2_EvictControl() – allows the owner or the platform firmware to designate objects that are to
   remain TPM-resident over TPM2_Startup() events. This command will return a new handle.

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
