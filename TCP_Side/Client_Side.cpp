#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "Header.h"

#pragma comment(lib, "Ws2_32.lib")

using std::cout;
using std::cin;
using std::string;
using std::endl;

/*
README.md
-------------------------------------------------------------------
Please recompile the program before running it
g++ Host_Side.cpp Encryption_Protocol.cpp -o Host_Side.exe -lws2_32
g++ Client_Side.cpp Encryption_Protocol.cpp -o Client_Side.exe -lws2_32
*/

std::mutex output_mutex;
string current_input;
std::atomic<bool> is_typing(false);

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    cout << "Connecting to host...\n";
    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cout << "Failed to connect to host!\n";
        closesocket(sock);
        WSACleanup();
        cin.get();
        return 1;
    }

    cout << "Connected to host!\n";

    key_exchange();

    string key = "Secret_Key";
    std::atomic<bool> running(true);
    std::atomic<bool> remote_quit(false);

    std::thread receiver([&]() {
        char buffer[1024];
        while (running) {
            int bytesReceived = recv(sock, buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0) { 
                running = false;
                remote_quit = true;
                break; 
            }
            string ciphertext(buffer, bytesReceived);
            string decrypted = decrypt_message(ciphertext, key);
            
            if (decrypted == "QUIT") { 
                running = false;
                remote_quit = true;
                shutdown(sock, SD_BOTH);
                
                std::lock_guard<std::mutex> lock(output_mutex);
                cout << "\r";
                for (size_t i = 0; i < current_input.length() + 8; i++) {
                    cout << " ";
                }
                cout << "\r";
                cout << "\nHost has disconnected. Press enter to exit." << endl;
                current_input.clear();
                break; 
            }
            
            {
                std::lock_guard<std::mutex> lock(output_mutex);
                string saved_input = current_input;
                cout << "\r";
                for (size_t i = 0; i < current_input.length() + 8; i++) {
                    cout << " ";
                }
                cout << "\r";
                cout << "Host: " << decrypted << endl;
                cout << "Client: " << saved_input << std::flush;
            }
        }
    });

    std::thread sender([&]() {
        cout << "Client: " << std::flush;
        while (running) {
            string msg;
            
            {
                std::lock_guard<std::mutex> lock(output_mutex);
                current_input.clear();
            }
            
            is_typing = true;
            getline(cin, msg);
            is_typing = false;
            
            if (!running) {
                break;
            }
            
            string encrypted = encrypt_message(msg, key);
            int sent = send(sock, encrypted.c_str(), encrypted.size(), 0);
            if (sent == SOCKET_ERROR) {
                running = false;
                break;
            }
            
            if (msg == "QUIT") {
                running = false;
                shutdown(sock, SD_SEND);
                cout << "You have disconnected. Press enter to quit the programme.";
                break;
            }
            
            if (running) {
                cout << "Client: " << std::flush;
            }
        }
    });

    sender.join();
    receiver.join();

    if (remote_quit) {
        string dummy;
        getline(cin, dummy);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
