#pragma once
#include <string>
#include <iostream>
#include "InitiatorNetwork.h"
class Initiator {
private:
    std::string ikeSPI;
    std::string peerSPI;
    std::string dhGroup;
    std::string encryptionAlgorithm;
    std::string integrityAlgorithm;
    std::string identity;
    std::string nonce;
    std::string sharedSecret;
    std::string trafficSelectors;
    std::string state;

    InitiatorNetwork& network;

public:
    // Constructor
    Initiator(InitiatorNetwork& net) : network(net) 
    {
        std::cout << "Initiator created." << std::endl;
    }

    // IKEv2 Phases
    void generateKeys();
    void buildIKE_SA_INIT();
    void processIKE_SA_INIT_Response();
    void buildIKE_AUTH();
    void processIKE_AUTH_Response();
    void authenticate();
    void createChildSA();
    void buildCREATE_CHILD_SA();
    void sendInformational();
    void buildInformationalMessage();

    // Cryptographic Operations
    void encryptPacket();
    void decryptPacket();

    void logState();
};
