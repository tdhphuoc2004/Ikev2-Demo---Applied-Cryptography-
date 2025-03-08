#include "Responder.h"

#include "ResponderIKEHeader.h"
#include "ResponderIKEMessage.h"
#include "ResponderIKEPayload.h"

#include "ResponderCrypto.h"
#include "ResponderCertificate.h"


std::string Responder::getDHprivatekey()
{
	return _privatekey;
}

std::string Responder::getDHpublickey()
{
	return _publickey;
}

std::string Responder::getNonceI()
{
	return _nonceI;
}

std::string Responder::getNonceR()
{
    return _nonceR;
}

std::string Responder::getsharedSecret()
{
	return _sharedSecret;
}

void Responder::processIKE_SA_INIT(IKEMessage &request)
{
    std::cout << "STEP 1.1 - PROCESS IKE SA INIT" << std::endl; 
	std::vector<uint8_t> binaryData = _network.receivePacket(); 
	// Parsing packet first
    request.parseIKEmessage(binaryData);

	// Getting Key and Nonce 
	std::string InitiatorDHKey = binaryToHex(request.payloads[0].data);
	ResponderCrypto::generateDHKey(_privatekey, _publickey);

	std::cout << "Generating responder private key:" << _privatekey << std::endl;
	std::cout << "Generating responder public key:" << _publickey << std::endl;
    std::cout << "Receiving initiator public key:" << InitiatorDHKey << std::endl;

	ResponderCrypto::calculateSharedSecret(InitiatorDHKey, _privatekey, _sharedSecret);
	std::cout << "Shared Secret:" << _sharedSecret << std::endl; 

	_nonceI = binaryToHex(request.payloads[1].data);
    std::cout << "Nonce from initator:" << _nonceI <<  std::endl;

    std::cout << std::endl;
}

void Responder::buildIKE_SA_INIT_Response(IKEMessage request)
{
    std::cout << "STEP 1.2 - SA IKE INIT RESPONSE" << std::endl;
    IKEMessage response;
    // Set Up IKE Header
    _peerSPI = request.header.initiatorSPI; // Copy from initiator request
    response.header.initiatorSPI = _peerSPI;
    _ikeSPI = generateSPI();
    response.header.responderSPI = _ikeSPI;
    response.header.nextPayload = static_cast<uint8_t> (PayloadType::KE);
    response.header.minorVersion = 0;
    response.header.exchangeType = static_cast<uint8_t> (IKEExchangeType::SA_INIT);
    response.header.messageID = request.header.messageID;  

    // Build KE Payload 
    IKEPayload kePayload = buildKEPayload(_publickey, PayloadType::NONCE);

    // Build Nonce payload 
    ResponderCrypto::generateNonce(_nonceR); 
    std::cout << "Nonce will be sent to initator:" << _nonceR << std::endl;
    IKEPayload noncePayload = buildNoncePayload(_nonceR, PayloadType::CERTREQ);

    // Build CAREQ payload 
    const std::string caName = "/C=VN/O=GROUP5/CN=My Root CA";
    IKEPayload careqPayload = buildCAREQPayload(caName, PayloadType::NONE);

    response.payloads.push_back(kePayload);
    response.payloads.push_back(noncePayload);
    response.payloads.push_back(careqPayload); 

    // Calculate total IKE message length
    uint32_t totalLength = IKE_HEADER_SIZE;
    for (auto payload : response.payloads)
    {
        totalLength += payload.payloadLength;
    }

    response.header.length = totalLength;

    // Send it 
    std::vector<uint8_t> binarymessage = response.toByteArray();
    _network.sendPacket(binarymessage);


    // Calculating SKEYSEED
    std::cout << std::endl;
    std::cout << "------------CALCULATING KEY MATERIALS------------" << std::endl; 
    _skeyseed = ResponderCrypto::generateSKEYSEED(_sharedSecret, _nonceI, _nonceR);
    std::cout << "Skeyseed:" << _skeyseed << std::endl;
    // Deriving keys 
    ResponderCrypto::deriveKeys(_skeyseed, _nonceI, _nonceR, _peerSPI, _ikeSPI, _sk_d, _sk_ai, _sk_ar, _sk_ei, _sk_er);
    std::cout << "Key child SA:" << _sk_d << std::endl;
    std::cout << "Key auth initiator:" << _sk_ai << std::endl;
    std::cout << "Key auth responder:" << _sk_ar << std::endl;
    std::cout << "Key encrypt initiator:" << _sk_ei << std::endl;
    std::cout << "Key encrypt responder:" << _sk_er << std::endl;

    std::cout << std::endl;
}

void Responder::processIKE_AUTH()
{
    std::cout << "STEP 1.3 - Process IKE AUTH" << std::endl;
   
}