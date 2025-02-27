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
	std::vector<uint8_t> binaryData = _network.receivePacket(); 
	// Parsing packet first
    request.parseIKEmessage(binaryData);

	// Get Key and Nonce 
	std::string InitiatorDHKey = binaryToHex(request.payloads[0].data);
	ResponderCrypto::generateDHKey(_privatekey, _publickey);
	std::cout << "Responder private key:" << _privatekey << std::endl;
	std::cout << "Responder public key:" << _publickey << std::endl;

	ResponderCrypto::calculateSharedSecret(InitiatorDHKey, _privatekey, _sharedSecret);
	std::cout << "shared Secret:" << _sharedSecret << std::endl; 

	_nonceI = binaryToHex(request.payloads[1].data);
    std::cout << "Nonce from initator:" << _nonceI <<  std::endl;
}

void Responder::buildIKE_SA_INIT_Response(IKEMessage request)
{
    IKEMessage response;

    // Set Up IKE Header
    _peerSPI = request.header.initiatorSPI; // Copy from initiator request
    response.header.initiatorSPI = _peerSPI;
    _ikeSPI = generateSPI();
    response.header.responderSPI = _ikeSPI;
    response.header.nextPayload = static_cast<uint8_t> (PayloadType::KE);
    response.header.minorVersion = 0;
    response.header.exchangeType = static_cast<uint8_t> (IKEExchangeType::SA_INIT);
    response.header.messageID = request.header.messageID;  // Message ID should match Initiator's

    //// Build SA Payload (Match Initiator’s cryptographic suite)
    //IKEPayload saPayload = buildSAPayload();
    //response.payloads.push_back(saPayload);

    // Build KE Payload 
    IKEPayload kePayload = buildKEPayload(_publickey, PayloadType::NONCE);

    // Build Nonce payload 
    ResponderCrypto::generateNonce(_nonceR); 
    std::cout << "Nonce will sent to initator:" << _nonceR << std::endl;
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
    std::cout << "Message length:" << totalLength << std::endl;


    // Send it 
    std::vector<uint8_t> binarymessage = response.toByteArray();
    _network.sendPacket(binarymessage);

}

void Responder::processIKE_AUTH()
{
    // Calculating SKEYSEED
    _skeyseed = ResponderCrypto::generateSKEYSEED(_sharedSecret, _nonceI, _nonceR);
    std::cout << "Skeyseed:" << _skeyseed << std::endl;
    std::cout << "my SPI:" << _ikeSPI << std::endl;
    std::cout << "peer SPI:" << _peerSPI << std::endl;
    // Deriving keys 
    ResponderCrypto::deriveKeys(_skeyseed, _nonceI, _nonceR, _ikeSPI, _peerSPI, _sk_d, _sk_ai, _sk_ar, _sk_ei, _sk_er);
    std::cout << "==================" << std::endl;
    std::cout << "Key child SA:" << _sk_d << std::endl;
    std::cout << "Key auth initiator:" << _sk_ai << std::endl;
    std::cout << "Key auth responder:" << _sk_ar << std::endl;
    std::cout << "Key encrypt initiator:" << _sk_ei << std::endl;
    std::cout << "Key encrypt responder:" << _sk_er << std::endl;
}