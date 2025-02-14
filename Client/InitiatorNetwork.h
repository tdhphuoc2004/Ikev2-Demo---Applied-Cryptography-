#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <iostream>

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
    void sendPacket(const std::string& msg);
    std::string receivePacket();
};
