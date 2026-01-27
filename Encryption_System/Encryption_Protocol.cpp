#include <algorithm>
#include <string>
#include <utility>
#include <sodium.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h> 
#include <openssl/rand.h>
#include <stdexcept>
#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <vector>
#include <conio.h>
#include "Header.h"

using std::cout;
using std::cin;
using std::copy;
using std::string;
using std::pair;
using std::vector;

const unsigned char PROTOCOL_VERSION = 1;

struct Ed25519KeyPair {
    vector<unsigned char> public_key;
    vector<unsigned char> secret_key;
};

vector<unsigned char> Initialisation(SOCKET sock, bool is_host){
    Ed25519KeyPair sign_key;
    sign_key.public_key.resize(crypto_sign_PUBLICKEYBYTES);
    sign_key.secret_key.resize(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(sign_key.public_key.data(), sign_key.secret_key.data());
    
    vector<unsigned char> Private_ECDH = ECDH_Private_Key_Generation();
    BIGNUM* Public_ECDH = ECDH_Public_Key_Calculator(Private_ECDH);
    
    vector<unsigned char> Public_ECDH_bytes(32);
    BN_bn2binpad(Public_ECDH, Public_ECDH_bytes.data(), 32);
    
    vector<unsigned char> nonce_vec = Random_Bytes(1);
    unsigned char nonce = nonce_vec[0];
    
    vector<unsigned char> message_to_sign;
    message_to_sign.insert(message_to_sign.end(), Public_ECDH_bytes.begin(), Public_ECDH_bytes.end());
    message_to_sign.push_back(nonce);
    message_to_sign.push_back(PROTOCOL_VERSION);
    
    vector<unsigned char> signature(crypto_sign_BYTES);
    crypto_sign_detached(signature.data(), nullptr, message_to_sign.data(), message_to_sign.size(), sign_key.secret_key.data());
    
    uint32_t pub_key_size = Public_ECDH_bytes.size();
    uint32_t sign_pub_key_size = sign_key.public_key.size();
    uint32_t signature_size = signature.size();

    send(sock, (char*)&pub_key_size, sizeof(uint32_t), 0);
    send(sock, (char*)Public_ECDH_bytes.data(), pub_key_size, 0);
    send(sock, (char*)&nonce, sizeof(unsigned char), 0);
    send(sock, (char*)&sign_pub_key_size, sizeof(uint32_t), 0);
    send(sock, (char*)sign_key.public_key.data(), sign_pub_key_size, 0);
    send(sock, (char*)&signature_size, sizeof(uint32_t), 0);
    send(sock, (char*)signature.data(), signature_size, 0);
    
    uint32_t B_pub_key_size, B_sign_pub_key_size, B_signature_size;
    unsigned char B_nonce;
    
    recv(sock, (char*)&B_pub_key_size, sizeof(uint32_t), 0);
    vector<unsigned char> B_Public_ECDH_bytes(B_pub_key_size);
    recv(sock, (char*)B_Public_ECDH_bytes.data(), B_pub_key_size, 0);
    recv(sock, (char*)&B_nonce, sizeof(unsigned char), 0);
    recv(sock, (char*)&B_sign_pub_key_size, sizeof(uint32_t), 0);
    vector<unsigned char> B_sign_public_key(B_sign_pub_key_size);
    recv(sock, (char*)B_sign_public_key.data(), B_sign_pub_key_size, 0);
    recv(sock, (char*)&B_signature_size, sizeof(uint32_t), 0);
    vector<unsigned char> B_signature(B_signature_size);
    recv(sock, (char*)B_signature.data(), B_signature_size, 0);

    vector<unsigned char> B_message_to_verify;
    B_message_to_verify.insert(B_message_to_verify.end(), B_Public_ECDH_bytes.begin(), B_Public_ECDH_bytes.end());
    B_message_to_verify.push_back(B_nonce);
    B_message_to_verify.push_back(PROTOCOL_VERSION);
    
    int verification = crypto_sign_verify_detached(
        B_signature.data(),
        B_message_to_verify.data(),
        B_message_to_verify.size(),
        B_sign_public_key.data()
    );
    
    if (verification != 0) {
        BN_free(Public_ECDH);
        throw std::runtime_error("Signature Verification Failed");
    }
    
    if (!ECDH_Verification(B_Public_ECDH_bytes)) {
        BN_free(Public_ECDH);
        throw std::runtime_error("Invalid ECDH Key");
    }
    
    BIGNUM* B_Public_ECDH = BN_bin2bn(B_Public_ECDH_bytes.data(), B_Public_ECDH_bytes.size(), NULL);
    BIGNUM* Private_ECDH_BN = BN_bin2bn(Private_ECDH.data(), Private_ECDH.size(), NULL);
    BIGNUM* ECDH_Shared_Secret = ECDH_Shared_Key(B_Public_ECDH, Private_ECDH_BN);
    vector<unsigned char> Shared_Key = HKDF_SHA256(ECDH_Shared_Secret);
    
    BN_free(Public_ECDH);
    BN_free(B_Public_ECDH);
    BN_free(Private_ECDH_BN);
    BN_free(ECDH_Shared_Secret);
    
    return Shared_Key;
}

vector<unsigned char> Random_Bytes(size_t length){
    vector<unsigned char> buf(length);
    randombytes_buf(buf.data(), length);
    
    return buf;
}

vector<unsigned char> Hash_SHA256(vector<unsigned char>& unhashed_text){ 
    vector<unsigned char> hashed_text(SHA256_DIGEST_LENGTH);
    SHA256(unhashed_text.data(), unhashed_text.size(), hashed_text.data());

    return hashed_text;
}

vector<unsigned char> ECDH_Private_Key_Generation(){
    vector<unsigned char> ECDH_private_key = Random_Bytes(crypto_scalarmult_SCALARBYTES);

    ECDH_private_key[0] &= 248;
    ECDH_private_key[31] &= 127;
    ECDH_private_key[31] |= 64;

    return ECDH_private_key;
}

BIGNUM* ECDH_Public_Key_Calculator(const vector<unsigned char>& ECDH_private_key){
    vector<unsigned char> public_key_bytes(32);

    if (crypto_scalarmult_base(public_key_bytes.data(), ECDH_private_key.data()) != 0) {
        throw std::runtime_error("crypto_scalarmult_base failed");
    }

    BIGNUM* Public_Key = BN_bin2bn(public_key_bytes.data(), public_key_bytes.size(), NULL);
    return Public_Key;
}

bool ECDH_Verification(const vector<unsigned char> ECDH_public_key){
    if (ECDH_public_key.size() != 32){ 
        return false;
    }

    return true;
}

BIGNUM* ECDH_Shared_Key(const BIGNUM* B_Public_ECDH, const BIGNUM* Private_ECDH){
    vector<unsigned char> private_key_bytes(32);
    vector<unsigned char> public_key_bytes(32);
    BN_bn2binpad(Private_ECDH, private_key_bytes.data(), 32);
    BN_bn2binpad(B_Public_ECDH, public_key_bytes.data(), 32);
    vector<unsigned char> shared_secret(32);

    if (crypto_scalarmult(shared_secret.data(), private_key_bytes.data(), public_key_bytes.data()) != 0) {
        throw std::runtime_error("crypto_scalarmult failed");
    }

    BIGNUM* Shared_Key = BN_bin2bn(shared_secret.data(), shared_secret.size(), NULL);
    return Shared_Key;
}

vector<unsigned char> HMAC_SHA256(const vector<unsigned char> Input, const vector<unsigned char> Salt){
    vector<unsigned char> Padded_Input(64, 0);
    copy(Salt.begin(), Salt.end(), Padded_Input.begin());
    vector<unsigned char> Inner_Pad(64);
    vector<unsigned char> Outer_Pad(64);

    for (size_t i = 0; i < 64; i++) { 
        Inner_Pad[i] = Padded_Input[i] ^ 0x36;
        Outer_Pad[i] = Padded_Input[i] ^ 0x5c;
    };

    vector<unsigned char> Inner_String = Inner_Pad;
    Inner_String.insert(Inner_String.end(), Input.begin(), Input.end());
    vector<unsigned char> Inner_Digest = Hash_SHA256(Inner_String);
    vector<unsigned char> Outer_String = Outer_Pad;
    Outer_String.insert(Outer_String.end(), Inner_Digest.begin(), Inner_Digest.end());
    vector<unsigned char> Output = Hash_SHA256(Outer_String);

    return Output;
}

vector<unsigned char> HKDF_SHA256(const BIGNUM* Shared_Key){
    vector<unsigned char> IKM(32);
    BN_bn2binpad(Shared_Key, IKM.data(), IKM.size());\

    vector<unsigned char> salt(32, 0);
    vector<unsigned char> PRK = HMAC_SHA256(IKM, salt);
    vector<unsigned char> Message = {0x01};
    vector<unsigned char> OKM = HMAC_SHA256(Message, PRK);

    OKM.resize(32);
    return OKM;
}

vector<unsigned char> AES_GCM_256_Encryption(const string& Plaintext, const vector<unsigned char>& Key){
    vector<unsigned char> Ciphertext(Plaintext.size());
    vector<unsigned char> Tag(16);
    vector<unsigned char> Nonce = Random_Bytes(12);
    int Length;
    int Final_Length;
    EVP_CIPHER_CTX* workspace = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(workspace, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(workspace, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(workspace, NULL, NULL, Key.data(), Nonce.data());
    EVP_EncryptUpdate(workspace, Ciphertext.data(), &Length, (unsigned char*)Plaintext.data(), Plaintext.size());
    EVP_EncryptFinal_ex(workspace, Ciphertext.data() + Length, &Final_Length);
    EVP_CIPHER_CTX_ctrl(workspace, EVP_CTRL_GCM_GET_TAG, 16, Tag.data());

    vector<unsigned char> IV_Ciphertext_Tag;
    IV_Ciphertext_Tag.insert(IV_Ciphertext_Tag.end(), Nonce.begin(), Nonce.end());
    IV_Ciphertext_Tag.insert(IV_Ciphertext_Tag.end(), Ciphertext.begin(), Ciphertext.begin() + Length + Final_Length);
    IV_Ciphertext_Tag.insert(IV_Ciphertext_Tag.end(), Tag.begin(), Tag.end());
    EVP_CIPHER_CTX_free(workspace);

    return IV_Ciphertext_Tag;
}

string AES_GCM_256_Decryption(const vector<unsigned char> IV_Ciphertext_Tag, const vector<unsigned char> Key){
    vector<unsigned char> Nonce(IV_Ciphertext_Tag.begin(), IV_Ciphertext_Tag.begin() + 12);
    vector<unsigned char> Tag(IV_Ciphertext_Tag.end() - 16, IV_Ciphertext_Tag.end());
    vector<unsigned char> Ciphertext(IV_Ciphertext_Tag.begin() + 12, IV_Ciphertext_Tag.end() - 16);
    EVP_CIPHER_CTX* workspace = EVP_CIPHER_CTX_new();
    vector<unsigned char> Plaintext(Ciphertext.size());
    int Length;
    int Final_Length;

    EVP_DecryptInit_ex(workspace, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(workspace, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(workspace, NULL, NULL, Key.data(), Nonce.data());
    EVP_DecryptUpdate(workspace, Plaintext.data(), &Length, Ciphertext.data(), Ciphertext.size());
    EVP_CIPHER_CTX_ctrl(workspace, EVP_CTRL_GCM_SET_TAG, 16, Tag.data());

    int Authentication = EVP_DecryptFinal_ex(workspace, Plaintext.data() + Length, &Final_Length);
    if (Authentication <= 0) {
        EVP_CIPHER_CTX_free(workspace);
        throw std::runtime_error("Authentication Failed");
    }

    Plaintext.resize(Length + Final_Length);
    EVP_CIPHER_CTX_free(workspace);
    return string(Plaintext.begin(), Plaintext.end());
}
