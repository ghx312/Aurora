# Aurora (Incomplete)  
## Description
- Aurora is an end-to-end encryption messaging service designed to guarantee confidentiality and authenticity by using modern cryptographic primitives
- It ensures that all messages are resistant to tampering and unauthorised access, allowing for private and secure communication.
- Aurora does not retain any user information, messaging history, or metadata.

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
C++ Compiler (g++ 9.0+ or MSVC with C++17 support)
OpenSSL
libsodium

---
## Disclaimer  
Aurora is intended for research and educational purposes only. Use at your own risk.
Any vulnerabilities found, please send an email to wongpinrui2009@gmail.com
***
