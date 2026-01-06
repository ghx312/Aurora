# RSA-Signed Ephemeral ECDH (RSE-ECDH)

## Overview

RSA-Signed Ephemeral Elliptic Curve Diffie–Hellman (RSE-ECDH) is a TCP-based, mutually authenticated key exchange and secure channel protocol. The protocol authenticates ephemeral ECDH key material using long-term RSA-PSS signature keys and establishes a forward-secure encrypted communication channel using symmetric authenticated encryption.

RSE-ECDH is a cryptographic protocol, not an encryption algorithm, and is layered above a reliable byte-stream transport such as TCP.

---

## Design Goals

- Mutual authentication of communicating parties
- Forward secrecy via ephemeral Diffie–Hellman key exchange
- Confidentiality and integrity of application data
- Use of well-established cryptographic primitives
- Clear separation between long-term identity keys and per-session key material

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

- **Mutual Authentication:** Each party verifies the identity of the peer using RSA-PSS signatures.
- **Forward Secrecy:** Compromise of long-term RSA keys does not compromise past session keys.
- **Confidentiality:** Application data is protected using authenticated encryption.
- **Integrity:** Modification of encrypted data is detected by AEAD authentication tags.

---

## Threat Model and Assumptions

- The adversary has full control over the network (eavesdropping, modification, replay).
- Long-term RSA private keys remain uncompromised during protocol execution.
- Cryptographic primitives are assumed to be secure when used as specified.
- Random number generation is assumed to be cryptographically secure.

---

## Non-Goals

- Protection against compromised endpoints
- Anonymity or identity hiding
- Resistance to traffic analysis
- Post-quantum security

---

## Implementation Notes

- Ephemeral ECDH key pairs must be generated per session and must not be reused.
- Nonces must be unique per encryption key when using AES-GCM.
- Protocol versioning must be included in the signed transcript to prevent downgrade attacks.

---

## Disclaimer

This project is intended for educational and experimental purposes. It has not been formally verified or independently audited and should not be used in production systems.
