#pragma once
#include <string>
#include <iostream>
#include "InitiatorNetwork.h"
#include "InitiatorIKEmessage.h"

class Initiator {
private:
   
    uint64_t _ikeSPI;
    uint64_t _peerSPI;

    const std::string _encryptionAlgorithm = "AES-CBC-128";
    const std::string _integrityAlgorithm = "HMAC-SHA-256-128";
    const std::string _prfAlgorithm = "HMAC-SHA-256";

    std::string _identity;

    // Nonce 
    std::string _nonce = "";

    // DH in Elliptic Curve 
    std::string _privatekey = "";
    std::string _publickey = ""; 
    std::string _sharedSecret = "";

    // Certificate 
    std::vector<uint8_t> _certReqRaw;   
    int _certEncoding;                  
    std::string _caIdentifier;         


    uint32_t _messageID; 

    std::string _trafficSelectors;
    std::string _state;

    InitiatorNetwork& _network;

public:
    std::string getDHprivatekey();
    std::string getDHpublickey(); 
    std::string getNonce(); 
    std::string getsharedSecret(); 

public:
    // Constructor
    Initiator(InitiatorNetwork& net) : _network(net) 
    {
        std::cout << "Initiator created using GCM-128 Security Suite." << std::endl;
        _messageID = 0; 
    }


    void buildIKE_SA_INIT();
    void processIKE_SA_INIT_Response(IKEMessage &response);

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
