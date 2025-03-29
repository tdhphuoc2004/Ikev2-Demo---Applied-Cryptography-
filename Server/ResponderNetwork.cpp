#include "ResponderNetwork.h"

// Constructor: Initializes Winsock and sets up TCP server
ResponderNetwork::ResponderNetwork(const std::string& ip, int port)
    : localIP(ip), localPort(port) {
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Error: Winsock initialization failed!" << std::endl;
        exit(EXIT_FAILURE);
    }

    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == INVALID_SOCKET) {
        std::cerr << "Error: Cannot create socket! Code: " << WSAGetLastError() << std::endl;
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(localPort);
    inet_pton(AF_INET, localIP.c_str(), &serverAddr.sin_addr);

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Error: Cannot bind socket! Code: " << WSAGetLastError() << std::endl;
        closesocket(serverSock);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    std::cout << "Responder listening on " << localIP << ":" << localPort << std::endl;
}

// Destructor: Closes sockets
ResponderNetwork::~ResponderNetwork() {
    closesocket(clientSock);
    closesocket(serverSock);
    WSACleanup();
}

// Start listening for TCP connections
void ResponderNetwork::startListening() {
    listen(serverSock, SOMAXCONN);
    std::cout << "Waiting for connection..." << std::endl;

    clientLen = sizeof(clientAddr);
    clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientLen);
    if (clientSock == INVALID_SOCKET) {
        std::cerr << "Error: Failed to accept connection!" << std::endl;
        closesocket(serverSock);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    std::cout << "Client connected!" << std::endl;
}

// Receive a packet
std::string ResponderNetwork::receiveTextMessage() {
    char buffer[1024] = { 0 };
    int receivedBytes = recv(clientSock, buffer, sizeof(buffer), 0);
    if (receivedBytes <= 0) {
        std::cerr << "Error: Failed to receive packet!" << std::endl;
        return "ERR";
    }

    std::string response(buffer, receivedBytes);
    std::cout << "Received: " << response << std::endl;
    return response;
}

// Send a response
void ResponderNetwork::sendTextMessage(const std::string& msg) {
    send(clientSock, msg.c_str(), msg.size(), 0);
    std::cout << "Sent: " << msg << std::endl;
}


void ResponderNetwork::sendPacket(const std::vector<uint8_t>& data) {
    send(clientSock, reinterpret_cast<const char*>(data.data()), data.size(), 0);

    // Optional: Print hex representation of sent data
 /*   std::cout << "Sent packet (" << data.size() << " bytes): ";
    for (const auto& byte : data) {
        printf("%02x ", byte);
    }
    std::cout << std::endl;*/
}

std::vector<uint8_t> ResponderNetwork::receivePacket() {
    std::vector<uint8_t> buffer(MAX_PACKET_SIZE);

    int receivedBytes = recv(clientSock, reinterpret_cast<char*>(buffer.data()), buffer.size(), 0);
    if (receivedBytes <= 0) {
        std::cerr << "Error: Failed to receive packet! Error code: " << WSAGetLastError() << std::endl;
        return std::vector<uint8_t>();
    }

    // Resize buffer to actual received bytes
    buffer.resize(receivedBytes);

    //// Debug output: print received bytes in hex
    //std::cout << "Received " << receivedBytes << " bytes: ";
    //for (const auto& byte : buffer) {
    //    printf("%02x ", byte);
    //}
    //std::cout << std::endl;

    return buffer;
}