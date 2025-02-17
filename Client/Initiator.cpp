#include "Initiator.h"
#include "InitiatorCrypto.h"
#include "IKEHeader.h"
#include "IKEPayload.h"
#include "IKEmessage.h"

#include <iostream>
#include <string>
#include <vector>

std::string Initiator::getdhKey()
{
	return dhKey; 
}

std::string Initiator::getNonce()
{
	return nonce;
}

std::string Initiator::getsharedSecret()
{
	return sharedSecret;
}

void Initiator::buildIKE_SA_INIT()
{
	// Generating Nonce and DH key first 
	InitiatorCrypto::generateDHKey(dhKey); 
	InitiatorCrypto::generateNonce(nonce);

	std::cout << "DH:" << dhKey << std::endl;
	std::cout << "nonce:" << nonce<< std::endl;

	// Build IKE header 
	IKEMessage message;
	message.header.initiatorSPI = generateSPI(); 
	message.header.responderSPI = 0;
	message.header.nextPayload = PAYLOAD_KE;
	message.header.majorVersion = 2;
	message.header.minorVersion = 0;
	message.header.exchangeType = IKE_SA_INIT;
	message.header.messageID = messageID;

	std::cout << "SPI:" << sizeof(message.header.initiatorSPI) << " " << sizeof(message.header.responderSPI) << std::endl; 
	// Build IKE payload 
	IKEPayload kePayload = buildKEPayload(dhKey);
	IKEPayload  noncePayload = buildNoncePayload(nonce);
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

	network.sendPacket(binarymessage);

	messageID++; 
}