#include <iostream>
#include <string>
#include "Header.h"

using std::cout;
using std::cin;
using std::string;

string key_exchange(){
    string demo_message = "Initialising Completed";
    return demo_message;
}

string encrypt_message(const string& msg, const string& key) {
    string result = msg;
    for (size_t i = 0; i < msg.size(); i++) {
        result[i] ^= key[i % key.size()];
    }
    return result;
}

string decrypt_message(const string& ciphertext, const string& key) {
    return encrypt_message(ciphertext, key);
}
