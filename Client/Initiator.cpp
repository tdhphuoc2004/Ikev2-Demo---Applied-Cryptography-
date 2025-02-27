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
	// Generating Nonce and DH key first 
	InitiatorCrypto::generateDHKey(_privatekey, _publickey); 
	InitiatorCrypto::generateNonce(_nonceI);

	std::cout << "DH private:" << _privatekey << std::endl;
	std::cout << "DH public:" << _publickey << std::endl;
	std::cout << "nonce will sent to responder:" << _nonceI << std::endl;

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
	std::cout << "Message length:" << totalLength << std::endl; 

	// Convert to binary format 
	std :: vector<uint8_t> binarymessage = message.toByteArray(); 

	_network.sendPacket(binarymessage);

	_messageID++; 
}

void Initiator::processIKE_SA_INIT_Response(IKEMessage &response)
{
	std::vector<uint8_t> binaryData = _network.receivePacket();
	response.parseIKEmessage(binaryData); 

	// Get SPI
	_peerSPI = response.header.responderSPI;
	//Get key and nonce 
	std::string ResponderPublicDHKey = binaryToHex(response.payloads[0].data);

	InitiatorCrypto::calculateSharedSecret(ResponderPublicDHKey, _privatekey, _sharedSecret);
	std::cout << "shared Secret:" << _sharedSecret << std::endl;

	_nonceR = binaryToHex(response.payloads[1].data);

	std::cout << "Nonce receive from responder:" << _nonceR << std::endl;

	// Get CERTREQ payload

	std::vector<uint8_t> certReqRaw = response.payloads[2].data;

	if (certReqRaw.size() >= (1 + SHA256_DIGEST_LENGTH)) {
		// Skip certificate type byte and convert hash to hex string
		_caIdentifier.clear();
		for (size_t i = 1; i < certReqRaw.size(); i++) {
			char hex[3];
			snprintf(hex, sizeof(hex), "%02x", certReqRaw[i]);
			_caIdentifier += hex;
		}

		std::cout << "CA Hash: " << _caIdentifier << std::endl;
	}
	else {
		std::cerr << "Error: Invalid CERTREQ payload size" << std::endl;
	}

}

void Initiator::buildIKE_AUTH()
{
	// Calculating SKEYSEED
	_skeyseed = InitiatorCrypto::generateSKEYSEED(_sharedSecret, _nonceI, _nonceR); 
	std::cout << "Skeyseed:" << _skeyseed << std::endl; 
	std::cout << "my SPI:" << _ikeSPI << std::endl; 
	std::cout << "peer SPI:" << _peerSPI << std::endl;
	// Deriving keys 
	InitiatorCrypto::deriveKeys(_skeyseed, _nonceI, _nonceR, _ikeSPI, _peerSPI, _sk_d, _sk_ai, _sk_ar, _sk_ei, _sk_er); 
	std::cout << "==================" << std::endl; 
	std::cout << "Key child SA:" << _sk_d << std::endl;
	std::cout << "Key auth initiator:" << _sk_ai << std::endl;
	std::cout << "Key auth responder:" << _sk_ar << std::endl;
	std::cout << "Key encrypt initiator:" << _sk_ei << std::endl;
	std::cout << "Key encrypt responder:" << _sk_er << std::endl;
}