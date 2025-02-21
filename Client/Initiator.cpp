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


std::string Initiator::getNonce()
{
	return _nonce;
}

std::string Initiator::getsharedSecret()
{
	return _sharedSecret;
}

void Initiator::buildIKE_SA_INIT()
{
	// Generating Nonce and DH key first 
	InitiatorCrypto::generateDHKey(_privatekey, _publickey); 
	InitiatorCrypto::generateNonce(_nonce);

	std::cout << "DH private:" << _privatekey << std::endl;
	std::cout << "DH public:" << _publickey << std::endl;
	std::cout << "nonce will sent to responder:" << _nonce<< std::endl;

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
	IKEPayload  noncePayload = buildNoncePayload(_nonce, PayloadType::NONE);
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

	_nonce = binaryToHex(response.payloads[1].data);

	std::cout << "Nonce receive from responder:" << _nonce << std::endl;

	// Get CERTREQ 
	// Store raw CERTREQ data
	_certReqRaw = response.payloads[2].data;

	// First byte indicates certificate encoding type
	_certEncoding = _certReqRaw[0];

	// Parse X509 name from the remaining data
	const unsigned char* namePtr = _certReqRaw.data() + 1;
	X509_NAME* name = d2i_X509_NAME(NULL, &namePtr, _certReqRaw.size() - 1);

	if (name) {
		char* nameStr = X509_NAME_oneline(name, NULL, 0);
		if (nameStr) {
			_caIdentifier = nameStr;
			OPENSSL_free(nameStr);
		}
		X509_NAME_free(name);
	}

	std::cout << "CA Identifier: " << _caIdentifier << std::endl;

}