#pragma once
#include <string>
#include <iostream>

class Initiator {
private:
    std::string localIP = "127.0.0.1";
    int localPort = 5000;
    std::string ikeSPI;
    std::string peerSPI;
    std::string dhGroup; // Group DH will be used (ex: Group 19,...) 
    std::string encryptionAlgorithm; // ex: AES-GCM-128
    std::string integrityAlgorithm; // ex: HMAC-SHA- 256 - 128
    std::string identity; // 
    std::string nonce; // Random number (Nonce) in SA_INIT
    std::string sharedSecret; // Common key of DH 
    std::string trafficSelectors;
    std::string state; // State connection of Initiator (ex: INIT, AUTHENTICATED, CHILD_SA,CREATED)

public:
    // Phase 1: Intialization
    Initiator(const std::string& localIP, const std::string& remoteIP);
    void generateKeys()

    // Phase 2: Create IKE_SA_INIT 
    void buildIKE_SA_INIT();
    void processIKE_SA_INIT_Response();

    // Phase 3: IKE_AUTH
    void buildIKE_AUTH();
    void processIKE_AUTH_Response();
    void authenticate();

    // Phase 4: Create_Child_SA
    void createChildSA();
    void buildCREATE_CHILD_SA();

    // Phase 5: INFORMATIONAL
    void sendInformational();
    void buildInformationalMessage();

    // Encrypting - Decrypting Operations 
    void encryptPacket();
    void decryptPacket();
    
    // Send - Receive Packets 
    std::string receivePacket();
    void sendPacket(const std::string& msg);

    void logState();
};
