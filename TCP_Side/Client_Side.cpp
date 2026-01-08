#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <conio.h>
#include "Header.h"

#pragma comment(lib, "Ws2_32.lib")

using std::cout;
using std::cin;
using std::string;
using std::endl;

/*
README.md
-------------------------------------------------------------------
On actual day, please recompile the program before running it
g++ Host_Side.cpp Encryption_Protocol.cpp -o Host_Side.exe -lws2_32
g++ Client_Side.cpp Encryption_Protocol.cpp -o Client_Side.exe -lws2_32

VSC Terminal:
.\Host_Side.exe

CMD/Second Computer:
cd C:\Users\wongp\Documents\Programming\Projects\Encrypted_Messaging -> Depending on other computer's directory
Client_Side.exe

Computers requires C++ to be downloaded, fix school computer
*/

std::mutex output_mutex;
std::mutex input_mutex;
string current_input;

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    cout << "Connecting to Host...\n";
    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cout << "Failed to connect to Host!\n";
        cout << "Press enter to exit." << endl;
        closesocket(sock);
        WSACleanup();
        cin.get();
        return 1;
    }

    cout << "Connected to Host!\n";

    string key = "Secret_Key";
    string init_msg = initialising();
    cout << init_msg << endl;

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
                std::lock_guard<std::mutex> output_lock(output_mutex);
                std::lock_guard<std::mutex> input_lock(input_mutex);
                
                string saved_input = current_input;
                
                cout << "\r";
                for (size_t i = 0; i < saved_input.length() + 8; i++) {
                    cout << " ";
                }
                cout << "\r";
                
                cout << "Host: " << decrypted << endl;
                
                if (!saved_input.empty()) {
                    cout << "Client: " << saved_input << std::flush;
                } else {
                    cout << "Client: " << std::flush;
                }
            }
        }
    });

    std::thread sender([&]() {
        cout << "Client: " << std::flush;
        while (running) {
            string msg;
            char ch;
            
            {
                std::lock_guard<std::mutex> lock(input_mutex);
                current_input.clear();
            }
            
            while (running) {
                if (_kbhit()) {
                    ch = _getch();
                    
                    if (ch == '\r') {
                        cout << endl;
                        break;
                    } else if (ch == '\b') {
                        if (!msg.empty()) {
                            msg.pop_back();
                            std::lock_guard<std::mutex> lock(input_mutex);
                            current_input = msg;
                            
                            std::lock_guard<std::mutex> output_lock(output_mutex);
                            cout << "\r";
                            for (size_t i = 0; i < msg.length() + 12; i++) {
                                cout << " ";
                            }
                            cout << "\rClient: " << msg << std::flush;
                        }
                    } else if (ch >= 32 && ch <= 126) {
                        msg += ch;
                        std::lock_guard<std::mutex> lock(input_mutex);
                        current_input = msg;
                        
                        std::lock_guard<std::mutex> output_lock(output_mutex);
                        cout << ch << std::flush;
                    }
                }
                Sleep(10);
            }
            
            if (!running) {
                break;
            }
            
            {
                std::lock_guard<std::mutex> lock(input_mutex);
                current_input.clear();
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
                cout << "Press enter to exit.";
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
