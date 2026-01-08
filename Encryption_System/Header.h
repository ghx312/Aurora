#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

using std::string;

string key_exchange();
string encrypt_message(const string& msg, const string& key);
string decrypt_message(const string& ciphertext, const string& key);

#endif
