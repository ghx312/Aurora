#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <conio.h>
#include "Header.h"

#pragma comment(lib, "Ws2_32.lib")

using std::cout;
using std::cin;
using std::vector;
using std::string;
using std::endl;

std::mutex output_mutex;
std::mutex input_mutex;
string current_input;

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    SOCKET serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == INVALID_SOCKET) {
        cout << "Failed to create socket! Error: " << WSAGetLastError() << endl;
        WSACleanup();
        cin.get();
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cout << "Failed to bind socket! Error: " << WSAGetLastError() << endl;
        cout << "Port 8080 may be in use. Press enter to exit." << endl;
        closesocket(serverSock);
        WSACleanup();
        cin.get();
        return 1;
    }
    
    listen(serverSock, SOMAXCONN);

    sockaddr_in clientAddr{};
    int clientSize = sizeof(clientAddr);
    SOCKET clientSock = accept(serverSock, (sockaddr*)&clientAddr, &clientSize);
    
    if (clientSock == INVALID_SOCKET) {
        cout << "Failed to accept connection! Error: " << WSAGetLastError() << endl;
        closesocket(serverSock);
        WSACleanup();
        cin.get();
        return 1;
    }

    vector<unsigned char> Shared_Key = Initialisation(clientSock, true);

    cout << "\n";
    cout << "                                    \n";
    cout << "     /\\                             \n";
    cout << "    /  \\  _   _ _ __ ___  _ __ __ _ \n";
    cout << "   / /\\ \\| | | | '__/ _ \\| '__/ _` |\n";
    cout << "  / ____ \\ |_| | | | (_) | | | (_| |\n";
    cout << " /_/    \\_\\__,_|_|  \\___/|_|  \\__,_|\n";
    cout << " Enter \"QUIT\" to quit \n";
    cout << "\n";

    std::atomic<bool> running(true);
    std::atomic<bool> remote_quit(false);

    std::thread receiver([&]() {
        char buffer[4096];
        while (running) {
            int bytesReceived = recv(clientSock, buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0) { 
                running = false;
                remote_quit = true;
                break; 
            }
            vector<unsigned char> ciphertext(buffer, buffer + bytesReceived);
            string decrypted = AES_GCM_256_Decryption(ciphertext, Shared_Key);
            
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
                std::lock_guard<std::mutex> output_lock(output_mutex);
                std::lock_guard<std::mutex> input_lock(input_mutex);
                
                string saved_input = current_input;
                
                cout << "\r";
                for (size_t i = 0; i < saved_input.length() + 6; i++) {
                    cout << " ";
                }
                cout << "\r";
                
                cout << "Client: " << decrypted << endl;
                
                if (!saved_input.empty()) {
                    cout << "Host: " << saved_input << std::flush;
                } else {
                    cout << "Host: " << std::flush;
                }
            }
        }
    });

    std::thread sender([&]() {
        cout << "Host: " << std::flush;
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
                            for (size_t i = 0; i < msg.length() + 10; i++) {
                                cout << " ";
                            }
                            cout << "\rHost: " << msg << std::flush;
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
            
            vector<unsigned char> encrypted = AES_GCM_256_Encryption(msg, Shared_Key);
            int sent = send(clientSock, (char*)encrypted.data(), encrypted.size(), 0);
            if (sent == SOCKET_ERROR) {
                running = false;
                break;
            }
            
            if (msg == "QUIT") {
                running = false;
                shutdown(clientSock, SD_SEND); 
                cout << "Press enter to exit.";
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
