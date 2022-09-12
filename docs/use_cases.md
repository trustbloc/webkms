# Use Cases

**Scenario 1**: server's lock is based on AWS key, user's lock uses local key

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
