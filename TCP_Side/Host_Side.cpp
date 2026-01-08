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

    SOCKET serverSock = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    bind(serverSock, (sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(serverSock, SOMAXCONN);

    cout << "Listening...\n";

    sockaddr_in clientAddr{};
    int clientSize = sizeof(clientAddr);
    SOCKET clientSock = accept(serverSock, (sockaddr*)&clientAddr, &clientSize);

    cout << "Connected to Client!\n";

    key_exchange();

    string key = "Secret_Key";
    std::atomic<bool> running(true);
    std::atomic<bool> remote_quit(false);

    std::thread receiver([&]() {
        char buffer[1024];
        while (running) {
            int bytesReceived = recv(clientSock, buffer, sizeof(buffer), 0);
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
                shutdown(clientSock, SD_BOTH);
                
                std::lock_guard<std::mutex> lock(output_mutex);
                cout << "\r";
                for (size_t i = 0; i < current_input.length() + 6; i++) {
                    cout << " ";
                }
                cout << "\r";
                cout << "\nClient has disconnected. Press enter to exit." << endl;
                current_input.clear();
                break; 
            }
            
            {
                std::lock_guard<std::mutex> lock(output_mutex);
                string saved_input = current_input;
                cout << "\r";
                for (size_t i = 0; i < current_input.length() + 6; i++) {
                    cout << " ";
                }
                cout << "\r";
                cout << "Client: " << decrypted << endl;
                cout << "Host: " << saved_input << std::flush;
            }
        }
    });

    std::thread sender([&]() {
        cout << "Host: " << std::flush;
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
            int sent = send(clientSock, encrypted.c_str(), encrypted.size(), 0);
            if (sent == SOCKET_ERROR) {
                running = false;
                break;
            }
            
            if (msg == "QUIT") {
                running = false;
                shutdown(clientSock, SD_SEND); 
                cout << "You have disconnected. Press enter to quit the programme.";
                break;
            }
            
            if (running) {
                cout << "Host: " << std::flush;
            }
        }
    });

    sender.join();
    receiver.join();

    if (remote_quit) {
        string dummy;
        getline(cin, dummy);
    }

    closesocket(clientSock);
    closesocket(serverSock);
    WSACleanup();
    return 0;
}
