#ifndef HEADER_H
#define HEADER_H

#include <string>
#include <vector>
#include <utility>
#include <openssl/bn.h>
#include <winsock2.h>

using std::vector;
using std::string;

extern const unsigned char PROTOCOL_VERSION;

vector<unsigned char> Initialisation(SOCKET sock, bool is_host);
vector<unsigned char> Random_Bytes(size_t length);
vector<unsigned char> Hash_SHA256(vector<unsigned char>& unhashed_text);
vector<unsigned char> ECDH_Private_Key_Generation();
BIGNUM* ECDH_Public_Key_Calculator(const vector<unsigned char>& ECDH_private_key);
bool ECDH_Verification(const vector<unsigned char> ECDH_public_key);
BIGNUM* ECDH_Shared_Key(const BIGNUM* B_Public_ECDH, const BIGNUM* Private_ECDH);
vector<unsigned char> HMAC_SHA256(const vector<unsigned char> Input, const vector<unsigned char> Salt);
vector<unsigned char> HKDF_SHA256(const BIGNUM* Shared_Key);
vector<unsigned char> AES_GCM_256_Encryption(const string& Plaintext, const vector<unsigned char>& Key);
string AES_GCM_256_Decryption(const vector<unsigned char> IV_Ciphertext_Tag, const vector<unsigned char> Key);

#endif
