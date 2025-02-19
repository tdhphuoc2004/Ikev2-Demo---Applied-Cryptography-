#pragma once
#include <string>
#include "ResponderNetwork.h"
#include "ResponderIKEMessage.h"


class Responder {
private:

    // IKEv2 security parameters
    uint64_t _ikeSPI;
    uint64_t _peerSPI;


    const std::string _encryptionAlgorithm = "AES-CBC-128";
    const std::string _integrityAlgorithm = "HMAC-SHA-256-128";
    const std::string _prfAlgorithm = "HMAC-SHA-256";

    uint32_t _messageID;

    std::string _privatekey = "";
    std::string _publickey = "";
    std::string _sharedSecret = "";

    // Authentication
    std::string _identity;
    std::string _nonce;

    // Traffic selectors
    std::string _trafficSelectors;

    // State tracking
    std::string _state;

    ResponderNetwork& _network;  // Reference to networking class

public:
    std::string getDHprivatekey();
    std::string getDHpublickey(); 
    std::string getNonce();
    std::string getsharedSecret();

public:
    // Constructor
    Responder(ResponderNetwork& net) : _network (net)
    {
        
        std::cout << "Responder created." << std::endl;
        
    }

    // IKEv2 Phases
    void processIKE_SA_INIT(IKEMessage& request);
    void buildIKE_SA_INIT_Response(IKEMessage request);

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
