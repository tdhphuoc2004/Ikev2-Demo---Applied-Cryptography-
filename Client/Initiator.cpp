#include "Initiator.h"
#include "InitiatorCrypto.h"

#include "InitiatorIKEmessage.h"
#include "InitiatorIKEPayload.h"
#include "InitiatorIKEHeader.h"
#include "InitiatorAuth.h"
#include "Utils.h"

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

void Initiator::buildIKE_AUTH(IKEMessage request)
{
	std::cout << "STEP 1.2 - BUILD IKE AUTH" << std::endl;

	// Build the Identity (IDi) payload using the initiator's identity.
	IKEPayload idPayload = buildIDPayload(_identity, PayloadType::CERT);
	std::vector<uint8_t> idBytes = idPayload.toByteArray();


	// Build the AUTH payload.
	// Concatenate of the IKE_SA_INIT request + Nr + prf(SK_pi, IDi')
	std::vector<uint8_t> signedOctets;
	std::vector<uint8_t> previousMessage = request.toByteArray(); 
	std::vector<uint8_t> Nr = stringToVector(_nonceR); 
	std::string idPayloadWithoutHeader = vectorToString(std::vector<uint8_t>(idPayload.data.begin() + PAYLOAD_HEADER_SIZE, idPayload.data.end()));


	std::string digestStr = InitiatorCrypto::prf(_sk_ai, idPayloadWithoutHeader);
	std::vector<uint8_t> prfOutput = stringToVector(digestStr); 
	
	signedOctets.insert(signedOctets.end(), previousMessage.begin(), previousMessage.end());
	signedOctets.insert(signedOctets.end(), Nr.begin(), Nr.end());
	signedOctets.insert(signedOctets.end(), prfOutput.begin(), prfOutput.end());

	// Build the signature using the initiator's private key 
	std::vector<uint8_t> signature = signData(_sk_ai, signedOctets);
	IKEPayload authPayload = buildAuthPayload(signature, PayloadType::NONE);
	std::vector<uint8_t> authBytes = authPayload.toByteArray();

	// Concatenate all payloads: [IDi || CERT || AUTH]
	std::vector<uint8_t> plaintext;
	plaintext.insert(plaintext.end(), idBytes.begin(), idBytes.end());
	plaintext.insert(plaintext.end(), authBytes.begin(), authBytes.end());

	// Wrap the plaintext into an Encrypted Payload (SK)
	// Use _sk_ei as the AES key 
	IKEPayload skPayload = buildEncryptedPayload(plaintext, _sk_ei, PayloadType::NONE);

	// Build the outer IKE message
	IKEMessage message;
	message.header.initiatorSPI = _ikeSPI;
	message.header.responderSPI = _peerSPI;

	// The outer message's nextPayload is the type of our single encrypted payload (SK)
	message.header.nextPayload = static_cast<uint8_t>(PayloadType::ENCR);
	message.header.majorVersion = 2;
	message.header.minorVersion = 0;
	message.header.exchangeType = static_cast<uint32_t>(IKEExchangeType::SA_AUTH);
	message.header.messageID = _messageID;

	message.payloads.push_back(skPayload);

	// Calculate the total message length.
	uint32_t totalLength = IKE_HEADER_SIZE;
	for (const auto& p : message.payloads) {
		totalLength += p.payloadLength;
	}
	message.header.length = totalLength;

	// Send the message
	std::vector<uint8_t> binaryMessage = message.toByteArray();
	_network.sendPacket(binaryMessage);
	_messageID++;
}