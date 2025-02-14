#include "InitiatorNetwork.h"

// Constructor: Initializes Winsock and sets up TCP connection
InitiatorNetwork::InitiatorNetwork(const std::string& ip, int port)
    : serverIP(ip), serverPort(port) {
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Error: Winsock initialization failed!" << std::endl;
        exit(EXIT_FAILURE);
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Error: Cannot create socket! Code: " << WSAGetLastError() << std::endl;
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);
}

// Destructor: Closes socket
InitiatorNetwork::~InitiatorNetwork() {
    closesocket(sock);
    WSACleanup();
}

// Connect to TCP Server
void InitiatorNetwork::connectToResponder() {
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Error: Cannot connect to server! Code: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        exit(EXIT_FAILURE);
    }
    std::cout << "Connected to server at " << serverIP << ":" << serverPort << std::endl;
}

// Send a packet
void InitiatorNetwork::sendPacket(const std::string& msg) {
    send(sock, msg.c_str(), msg.size(), 0);
    std::cout << "Sent: " << msg << std::endl;
}

// Receive a packet
std::string InitiatorNetwork::receivePacket() {
    char buffer[1024] = { 0 };
    int receivedBytes = recv(sock, buffer, sizeof(buffer), 0);
    if (receivedBytes <= 0) {
        std::cerr << "Error: Failed to receive packet!" << std::endl;
        return "ERR";
    }

    std::string response(buffer, receivedBytes);
    std::cout << "Received: " << response << std::endl;
    return response;
}
