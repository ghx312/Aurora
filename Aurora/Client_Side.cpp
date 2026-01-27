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

#pragma comment(lib, "Ws2_32.lib")

using std::cout;
using std::cin;
using std::string;
using std::endl;
using std::vector;
using std::atomic;

std::mutex output_mutex;
std::mutex input_mutex;
string current_input;

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        cout << "Failed to create socket! Error: " << WSAGetLastError() << endl;
        WSACleanup();
        cin.get();
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        cout << "Failed to connect to Host!\n";
        cout << "Error code: " << error << endl;
        cout << "Press enter to exit." << endl;
        closesocket(sock);
        WSACleanup();
        cin.get();
        return 1;
    }
    
    vector<unsigned char> Shared_Key = Initialisation(sock, false);

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
            int bytesReceived = recv(sock, buffer, sizeof(buffer), 0);
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
            
            vector<unsigned char> encrypted = AES_GCM_256_Encryption(msg, Shared_Key);
            int sent = send(sock, (char*)encrypted.data(), encrypted.size(), 0);
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
