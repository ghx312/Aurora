RSA-Signed Ephemeral Elliptic Curve Diffie–Hellman (RSE-ECDH) is a TCP-based, mutually authenticated key exchange and secure channel protocol.

The protocol uses long-term RSA key pairs to authenticate freshly generated ephemeral ECDH public keys via RSA-PSS signatures. Upon successful mutual authentication, both parties derive a shared secret using Elliptic Curve Diffie–Hellman. Symmetric session keys are derived from this shared secret using HKDF with SHA-256. Application data is protected using AES-256-GCM authenticated encryption.

The protocol provides mutual authentication, confidentiality, integrity, and forward secrecy, and is designed to operate over a reliable byte-stream transport such as TCP.
