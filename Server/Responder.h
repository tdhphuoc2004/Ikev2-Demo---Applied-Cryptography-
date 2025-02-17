#pragma once
#include <string>
#include "ResponderNetwork.h"

class Responder {
private:

    // IKEv2 security parameters
    std::string ikeSPI;
    std::string peerSPI;


    const std::string encryptionAlgorithm = "AES-CBC-128";
    const std::string integrityAlgorithm = "HMAC-SHA-256-128";
    const std::string prfAlgorithm = "HMAC-SHA-256";

    uint32_t messageID;

    std::string dhKey = "";
    std::string sharedSecret;

    // Authentication
    std::string identity;
    std::string nonce;

    // Traffic selectors
    std::string trafficSelectors;

    // State tracking
    std::string state;

    ResponderNetwork& network;  // Reference to networking class

public:
    std::string getdhKey();
    std::string getNonce();
    std::string getsharedSecret();

public:
    // Constructor
    Responder(ResponderNetwork& net) : network (net)
    {
        
        std::cout << "Responder created." << std::endl;
        
    }

    // IKEv2 Phases
    void processIKE_SA_INIT();
    void buildIKE_SA_INIT_Response();
    void processIKE_AUTH();
    void buildIKE_AUTH_Response();
    void processCREATE_CHILD_SA();
    void buildCREATE_CHILD_SA_Response();
    void processInformational();
    void buildInformationalResponse();

    // Cryptographic Operations
    void generateKeys();
    void encryptPacket();
    void decryptPacket();

    // Debugging
    void logState();
};
