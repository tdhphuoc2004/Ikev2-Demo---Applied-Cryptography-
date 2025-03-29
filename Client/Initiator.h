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

    std::string _identity = "Initiator@hcmus.com";
    std::string _peeridentity = ""; 

    // Nonce 
    std::string _nonceI = "";
    std::string _nonceR = "";

    // DH in Elliptic Curve 
    std::string _privatekey = "";
    std::string _publickey = ""; 
    std::string _sharedSecret = "";

    // SKEYSEED and cryptographic key 
    std::string _skeyseed;   
    std::string _sk_d;       
    std::string _sk_ai;      
    std::string _sk_ar;      
    std::string _sk_ei;      
    std::string _sk_er;      

    //  Authentication 
    std::string _authData;      
    std::string _peerAuthData;  

    uint32_t _messageID; 

    InitiatorNetwork& _network;

public:
    std::string getDHprivatekey();
    std::string getDHpublickey(); 
    std::string getNonceI(); 
    std::string getNonceR();
    std::string getsharedSecret(); 
    std::string getCAIndentifer(); 

public:
    // Constructor
    Initiator(InitiatorNetwork& net) : _network(net) 
    {
        _messageID = 0; 
        std::cout << "Initiator created." << std::endl;
    }

    IKEMessage buildIKE_SA_INIT();
    IKEMessage processIKE_SA_INIT_Response();
    void buildIKE_AUTH(IKEMessage saInitInitatorRequest);
    void processIKE_AUTH_Response(IKEMessage saInitResponderResponse);
};
