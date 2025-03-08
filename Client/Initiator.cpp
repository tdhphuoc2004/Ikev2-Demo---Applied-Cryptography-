#include "Initiator.h"
#include "InitiatorCrypto.h"

#include "InitiatorIKEmessage.h"
#include "InitiatorIKEPayload.h"
#include "InitiatorIKEHeader.h"

#include <iostream>
#include <string>
#include <vector>

std::string Initiator::getDHprivatekey()
{
	return _privatekey;
}

std::string Initiator::getDHpublickey()
{
	return _publickey;
}


std::string Initiator::getNonceI()
{
	return _nonceI;
}

std::string Initiator::getNonceR()
{
	return _nonceR;
}

std::string Initiator::getsharedSecret()
{
	return _sharedSecret;
}

std::string Initiator::getCAIndentifer()
{
	return _caIdentifier;
}

void Initiator::buildIKE_SA_INIT()
{
	std::cout << "STEP 1.1 - BUILD IKE SA INIT" << std::endl;
	// Generating Nonce and DH key first 
	InitiatorCrypto::generateDHKey(_privatekey, _publickey); 
	InitiatorCrypto::generateNonce(_nonceI);

	std::cout << "Generating initiator private key:" << _privatekey << std::endl;
	std::cout << "Generating initiator public key:" << _publickey << std::endl;
	std::cout << "Nonce will be sent to responder:" << _nonceI << std::endl;

	// Build IKE header 
	IKEMessage message;
	_ikeSPI = generateSPI(); 
	message.header.initiatorSPI = _ikeSPI; 
	_peerSPI = 0; 
	message.header.responderSPI = _peerSPI;
	message.header.nextPayload = static_cast<uint32_t>(PayloadType::KE);
	message.header.majorVersion = 2;
	message.header.minorVersion = 0;
	message.header.exchangeType = static_cast<uint32_t> (IKEExchangeType::SA_INIT);
	message.header.messageID = _messageID;

	// Build IKE payload 
	IKEPayload kePayload = buildKEPayload(_publickey, PayloadType::NONCE);
	IKEPayload  noncePayload = buildNoncePayload(_nonceI, PayloadType::NONE);
	message.payloads.push_back(kePayload); 
	message.payloads.push_back(noncePayload); 

	// Calculate total IKE message length
	uint32_t totalLength = IKE_HEADER_SIZE;
	for (auto payload : message.payloads)
	{
		totalLength += payload.payloadLength;  
	}

	message.header.length = totalLength;
	std :: vector<uint8_t> binarymessage = message.toByteArray(); 
	_network.sendPacket(binarymessage);
	_messageID++; 

	std::cout << std::endl;
}

void Initiator::processIKE_SA_INIT_Response(IKEMessage &response)
{
	std::cout << "STEP 1.2 - PROCESS IKE SA INIT RESPONSE" << std::endl;
	std::vector<uint8_t> binaryData = _network.receivePacket();
	response.parseIKEmessage(binaryData); 

	// Get SPI
	_peerSPI = response.header.responderSPI;
	//Get key and nonce 
	std::string ResponderPublicDHKey = binaryToHex(response.payloads[0].data);

	InitiatorCrypto::calculateSharedSecret(ResponderPublicDHKey, _privatekey, _sharedSecret);

	std::cout << "Receiving responder public key:" << ResponderPublicDHKey << std::endl; 
	std::cout << "shared Secret:" << _sharedSecret << std::endl;
	_nonceR = binaryToHex(response.payloads[1].data);
	std::cout << "Nonce receive from responder:" << _nonceR << std::endl;

	// Get CERTREQ payload
	std::vector<uint8_t> certReqRaw = response.payloads[2].data;

	if (certReqRaw.size() >= (1 + SHA256_DIGEST_LENGTH)) 
	{
		// Skip certificate type byte and convert hash to hex string
		_caIdentifier.clear();
		for (size_t i = 1; i < certReqRaw.size(); i++) 
		{
			char hex[3];
			snprintf(hex, sizeof(hex), "%02x", certReqRaw[i]);
			_caIdentifier += hex;
		}

		std::cout << "CA Hash: " << _caIdentifier << std::endl;
	}
	else 
	{
		std::cerr << "Error: Invalid CERTREQ payload size" << std::endl;
	}

	// Calculating SKEYSEED
	std::cout << std::endl;
	std::cout << "------------CALCULATING KEY MATERIALS------------" << std::endl;
	_skeyseed = InitiatorCrypto::generateSKEYSEED(_sharedSecret, _nonceI, _nonceR);
	std::cout << "Skeyseed:" << _skeyseed << std::endl;
	// Deriving keys 
	InitiatorCrypto::deriveKeys(_skeyseed, _nonceI, _nonceR, _ikeSPI, _peerSPI, _sk_d, _sk_ai, _sk_ar, _sk_ei, _sk_er);
	std::cout << "Key child SA:" << _sk_d << std::endl;
	std::cout << "Key auth initiator:" << _sk_ai << std::endl;
	std::cout << "Key auth responder:" << _sk_ar << std::endl;
	std::cout << "Key encrypt initiator:" << _sk_ei << std::endl;
	std::cout << "Key encrypt responder:" << _sk_er << std::endl;

	std::cout << std::endl;
}

void Initiator::buildIKE_AUTH()
{
	std::cout << "STEP 1.2 - BUILD IKE AUTH" << std::endl;
	
}