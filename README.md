# RSA-Signed Ephemeral ECDH

## Overview

---
## Cryptographic Primitives

- **Key Exchange:** Ephemeral Elliptic Curve Diffie–Hellman (ECDH)
- **Authentication:** RSA-PSS signatures with SHA-256
- **Key Derivation:** HKDF with SHA-256
- **Symmetric Encryption:** AES-256-GCM (AEAD)
- **Transport:** TCP

---
## Protocol Overview

1. Each party generates an ephemeral ECDH key pair for the session.
2. ECDH public keys and protocol metadata are signed using long-term RSA-PSS identity keys.
3. Signed ECDH public keys are exchanged and verified by both parties.
4. A shared secret is computed using ECDH.
5. Symmetric session keys are derived from the shared secret using HKDF-SHA256.
6. Application data is encrypted and authenticated using AES-256-GCM.

---
## Security Properties

 Integrity -> Ensure that the message has not been tampered with  
- Confidentiality -> Only the intended recipient can read the message  
- Authenticity -> Proves one's identity  
- Replay Protection -> Prevents attackers from using old messages as a way of decrypting the new messages  
- Forward Secrecy -> Keys continue to stay secure even after repeated usage  

Resistant against: 
- Man-In-The-Middle Attacks  
---
## Threat Model and Assumptions

- The adversary has full control over the network (eavesdropping, modification, replay).
- Long-term RSA private keys remain uncompromised during protocol execution.
- Cryptographic primitives are assumed to be secure when used as specified.
- Random number generation is assumed to be cryptographically secure.
---
## Disclaimer

---
