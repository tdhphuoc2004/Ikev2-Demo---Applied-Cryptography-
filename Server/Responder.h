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

    std::string _identity;

    // Nonce 
    std::string _nonceI = "";
    std::string _nonceR = "";

    // DH in Elliptic Curve 
    std::string _privatekey = "";
    std::string _publickey = "";
    std::string _sharedSecret = "";

    // Certificate   
    std::string _caIdentifier;
    std::string _certificate;
    std::string _peerCertificate;

    // SKEYSEED and cryptographic key 
    std::string _skeyseed;   // Giá tr? SKEYSEED tính t? DH & Nonce  
    std::string _sk_d;
    std::string _sk_ai;
    std::string _sk_ar;
    std::string _sk_ei;
    std::string _sk_er;

    //  Authentication 
    std::string _authData;      // AUTH payload g?i ?i  
    std::string _peerAuthData;  // AUTH payload nh?n ???c t? Responder  

    uint32_t _messageID;

    std::string _trafficSelectors;
    std::string _state;

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
    void processIKE_SA_INIT(IKEMessage& request);
    void buildIKE_SA_INIT_Response(IKEMessage request);

    void processIKE_AUTH();
    void buildIKE_AUTH_Response();
};
