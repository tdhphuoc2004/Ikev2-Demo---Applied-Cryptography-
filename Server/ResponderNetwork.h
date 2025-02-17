#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <iostream>
#include <vector>
#pragma comment(lib, "Ws2_32.lib")
#define MAX_PACKET_SIZE 4096

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

    std::string receiveTextMessage();
    void sendTextMessage(const std::string& msg);

    void sendPacket(const std::vector<uint8_t>& data); 
    std::vector<uint8_t> receivePacket(); 

};
