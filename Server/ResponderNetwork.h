#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

class ResponderNetwork {
private:
    SOCKET serverSock, clientSock;
    sockaddr_in serverAddr, clientAddr;
    WSADATA wsaData;
    int clientLen;

    std::string localIP;
    int localPort;

public:
    ResponderNetwork(const std::string& localIP, int localPort);
    ~ResponderNetwork();

    void startListening();
    std::string receivePacket();
    void sendPacket(const std::string& msg);
};
