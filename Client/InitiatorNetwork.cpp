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
void InitiatorNetwork::sendPacket(const std::vector<uint8_t>& data) {
    send(sock, reinterpret_cast<const char*>(data.data()), data.size(), 0);

    // Optional: Print hex representation of sent data
    std::cout << "Sent packet (" << data.size() << " bytes): ";
    for (const auto& byte : data) {
        printf("%02x ", byte);
    }
    std::cout << std::endl;
}

// Receive a packet
std::vector<uint8_t> InitiatorNetwork::receivePacket() {
    std::vector<uint8_t> buffer(MAX_PACKET_SIZE);

    int receivedBytes = recv(sock, reinterpret_cast<char*>(buffer.data()), buffer.size(), 0);
    if (receivedBytes <= 0) {
        std::cerr << "Error: Failed to receive packet! Error code: " << WSAGetLastError() << std::endl;
        return std::vector<uint8_t>();
    }

    // Resize buffer to actual received bytes
    buffer.resize(receivedBytes);

    // Debug output: print received bytes in hex
    std::cout << "Received " << receivedBytes << " bytes: ";
    for (const auto& byte : buffer) {
        printf("%02x ", byte);
    }
    std::cout << std::endl;

    return buffer;
}


void InitiatorNetwork::sendTextMessage(const std::string& msg) 
{
    send(sock, msg.c_str(), msg.length(), 0);
    std::cout << "Sent test message: " << msg << std::endl;
}

std::string InitiatorNetwork::receiveTextMessage() {
    char buffer[1024] = { 0 };
    int receivedBytes = recv(sock, buffer, sizeof(buffer), 0);
    if (receivedBytes <= 0) {
        std::cerr << "Error: Failed to receive test message!" << std::endl;
        return "ERR";
    }

    std::string response(buffer, receivedBytes);
    std::cout << "Received test message: " << response << std::endl;
    return response; 
}