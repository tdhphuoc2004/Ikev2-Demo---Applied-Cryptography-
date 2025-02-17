#include "Responder.h"
#include "IKEmessage.h"
#include "IKEPayload.h"
#include "IKEHeader.h"
#include "ResponderCrypto.h"
std::string Responder::getdhKey()
{
	return dhKey;
}

std::string Responder::getNonce()
{
	return nonce;
}

std::string Responder::getsharedSecret()
{
	return sharedSecret;
}

void Responder::processIKE_SA_INIT()
{
	std::vector<uint8_t> binaryData = network.receivePacket(); 
	// Parsing packet first
	IKEMessage message;
	message.parseIKEmessage(binaryData);
	// Get Key and Nonce 
	std::string InitiatorDHKey = binaryToHex(message.payloads[0].data); 
	ResponderCrypto::generateDHKey(dhKey);
	std::cout << dhKey << std::endl;
	ResponderCrypto::calculateSharedSecret(InitiatorDHKey, dhKey, sharedSecret);
	std::cout << "shared Secret:" << sharedSecret << std::endl; 

}
