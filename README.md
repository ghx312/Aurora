# RSA-Signed Ephemeral ECDH (Incomplete)

## Cryptographic Primitives

- **Key Exchange:** Ephemeral Elliptic Curve Diffie–Hellman (ECDH)
- **Authentication:** RSA-PSS signatures with SHA-256
- **Key Derivation:** HKDF with SHA-256
- **Symmetric Encryption:** AES-256-GCM (AEAD)
- **Transport:** TCP

---
## Security Properties

- Integrity -> Ensure that the message has not been tampered with  
- Confidentiality -> Only the intended recipient can read the message  
- Authenticity -> Proves one's identity  
- Replay Protection -> Prevents attackers from using old messages as a way of decrypting the new messages  
- Forward Secrecy -> Keys continue to stay secure even after repeated usage  

Resistant against: 
- Man-In-The-Middle Attacks

---
## Dependencies
C++ Compiler (Within VSC and/or Terminal)

---
## Disclaimer

Not ready for comercial use, use at your own risk, for educational purposes only.  
Any vulnerabilities found, please send an email to wongpinrui2009@gmail.com

---
