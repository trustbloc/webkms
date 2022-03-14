# Use Cases

**Scenario 1**: server's lock is based on AWS key, user's lock uses local key, no EDV

In this scenario, a key for the user's lock is created when the key store is created. That key is encrypted with an AWS
key and stored in the server's DB. When a working key is created for the user, it is encrypted with that stored lock key.
Before using, user's lock key should be decrypted with an AWS key.

```mermaid
    sequenceDiagram
        participant User
        participant KMS
        participant AWS
        participant Storage

        User->>KMS: create keystore {controller}
        KMS->>KMS: create lock key
        KMS->>AWS: encrypt lock key
        AWS-->>KMS: encrypted lock key
        KMS->>Storage: save encrypted lock key
        Storage-->>KMS: {key ID}
        KMS-->>User: {keystore URL, root ZCAPs}

        User->>KMS: create key {key type}
        KMS->>KMS: create key
        KMS->>Storage: get lock key
        Storage-->>KMS: encrypted lock key
        KMS->>AWS: decrypt lock key
        AWS-->>KMS: decrypted lock key
        KMS->>KMS: encrypt key with lock key
        KMS->>Storage: save encrypted key
        Storage-->>KMS: {key ID}
        KMS-->>User: {key URL, public key bytes}
```

**Scenario 2**: server's lock is based on local key, user's lock uses Shamir-based key, working keys are stored in EDV

Key for the server's lock is stored in a local file and the path to it is specified in a startup flag or environment
variable. When a key store is created, helper recipient and MAC keys for the EDV provider are created as well. They are
encrypted with a key from the local file (server's lock) and saved to the server's DB. These keys are associated with
a created key store to support EDV operations.

User's lock key is created on a fly using HKDF algorithm that expands the combined secret (from shares using Shamir
Secret Sharing) into a symmetric key. That key is used to encrypt/decrypt the user's working keys stored in EDV.

```mermaid
    sequenceDiagram
        participant User
        participant KMS
        participant DB
        participant EDV
        participant Auth as Auth Server

        User->>KMS: create keystore {controller, EDV vault URL and ZCAPs}
        loop for EDV recipient key, EDV MAC key
            KMS->>KMS: create key
            KMS->>KMS: encrypt key with server's local (master) key
            KMS->>DB: save encrypted key
            DB-->>KMS: {key ID}
        end
        KMS-->>User: {keystore URL, root ZCAPs}

        User->>KMS: create key {key type, secret share}
        KMS->>KMS: create key
        KMS->>Auth: get secret share
        Auth-->>KMS: secret share
        KMS->>KMS: create lock key on a fly from secret shares
        KMS->>KMS: encrypt key with lock key
        loop for EDV recipient key, EDV MAC key
            KMS->>DB: get key
            KMS->>KMS: decrypt key with server's local (master) key
        end
        KMS->>EDV: save encrypted key
        EDV-->>KMS: {key ID}
        KMS-->>User: {key URL, public key bytes}
```
