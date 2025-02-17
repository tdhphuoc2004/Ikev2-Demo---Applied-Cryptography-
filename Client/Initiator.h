#pragma once
#include <string>
#include <iostream>
#include "InitiatorNetwork.h"
class Initiator {
private:
    std::string ikeSPI;
    std::string peerSPI;

    const std::string encryptionAlgorithm = "AES-CBC-128";
    const std::string integrityAlgorithm = "HMAC-SHA-256-128";
    const std::string prfAlgorithm = "HMAC-SHA-256";

    std::string identity;
    std::string nonce = "";

    std::string dhKey = "";
    std::string sharedSecret;

    uint32_t messageID; 

    std::string trafficSelectors;
    std::string state;

    InitiatorNetwork& network;

public:
    std::string getdhKey(); 
    std::string getNonce(); 
    std::string getsharedSecret(); 

public:
    // Constructor
    Initiator(InitiatorNetwork& net) : network(net) 
    {
        std::cout << "Initiator created using GCM-128 Security Suite." << std::endl;
        messageID = 0; 
    }


    void buildIKE_SA_INIT();
    //void processIKE_SA_INIT_Response();

    //void buildIKE_AUTH();
    //void processIKE_AUTH_Response();
    //void authenticate();
    //void createChildSA();
    //void buildCREATE_CHILD_SA();
    //void sendInformational();
    //void buildInformationalMessage();

    //// Cryptographic Operations
    //void encryptPacket();
    //void decryptPacket();

    //void logState();
};
