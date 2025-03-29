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

    std::string _identity = "Responder@hcmus.com";
    std::string _peeridentity;

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

    ResponderNetwork& _network;

public:
    std::string getDHprivatekey();
    std::string getDHpublickey(); 
    std::string getNonceI();
    std::string getNonceR();
    std::string getsharedSecret();

public:
    // Constructor
    Responder(ResponderNetwork& net) : _network (net)
    {
        
        std::cout << "Responder created." << std::endl;
        
    }

    // IKEv2 Phases
    IKEMessage processIKE_SA_INIT();
    IKEMessage buildIKE_SA_INIT_Response();
    void processIKE_AUTH(IKEMessage saInitInitatorRequest);
    void buildIKE_AUTH_Response(IKEMessage saInitResponderResponse);
};
