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

std::string Responder::getNonce()
{
	return _nonce;
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

	_nonce = binaryToHex(request.payloads[1].data);
    std::cout << "Nonce from initator:" << _nonce <<  std::endl; 
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
    std::string nonce = ""; 
    ResponderCrypto::generateNonce(nonce); 
    std::cout << "Nonce will sent to initator:" << nonce << std::endl;
    IKEPayload noncePayload = buildNoncePayload(nonce, PayloadType::CERTREQ); 

    // Build CAREQ payload 
    EVP_PKEY* publickeyRSA = generate_rsa_key(1024); 
    X509* certificate = create_ca_certificate(publickeyRSA, 100); 
    IKEPayload careqPayload = buildCAREQPayload(certificate, PayloadType::NONE); 

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