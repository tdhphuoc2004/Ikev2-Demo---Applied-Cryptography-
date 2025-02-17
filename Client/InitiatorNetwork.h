#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <iostream>
#include <vector>
#define MAX_PACKET_SIZE 4096
#pragma comment(lib, "Ws2_32.lib")

class InitiatorNetwork {
private:
    SOCKET sock;
    sockaddr_in serverAddr;
    WSADATA wsaData;

    std::string serverIP;
    int serverPort;

public:
    InitiatorNetwork(const std::string& serverIP, int serverPort);
    ~InitiatorNetwork();

    void connectToResponder();
    void sendPacket(const std::vector<uint8_t>& data);
    std::vector<uint8_t> receivePacket();

    void sendTextMessage(const std::string& msg); 
    std::string receiveTextMessage(); 
};
