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
	message.header.nextPayload = PAYLOAD_KE;
	message.header.majorVersion = 2;
	message.header.minorVersion = 0;
	message.header.exchangeType = IKE_SA_INIT;
	message.header.messageID = _messageID;

	// Build IKE payload 
	IKEPayload kePayload = buildKEPayload(_publickey);
	IKEPayload  noncePayload = buildNoncePayload(_nonce);
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

	//Get key and nonce 
	std::string ResponderPublicDHKey = binaryToHex(response.payloads[0].data);

	InitiatorCrypto::calculateSharedSecret(ResponderPublicDHKey, _privatekey, _sharedSecret);
	std::cout << "shared Secret:" << _sharedSecret << std::endl;

	_nonce = binaryToHex(response.payloads[1].data);

	std::cout << "Nonce receive from responder:" << _nonce << std::endl;

}