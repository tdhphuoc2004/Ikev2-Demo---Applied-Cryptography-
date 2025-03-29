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
#include <iomanip>

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


IKEMessage Initiator::buildIKE_SA_INIT()
{
	std::cout << "STEP 1 - BUILD IKE SA INIT" << std::endl;
	// Generating Nonce and DH key first 
	InitiatorCrypto::generateDHKey(_privatekey, _publickey); 
	InitiatorCrypto::generateNonce(_nonceI);

	std::cout << "Generating initiator private key:" << _privatekey << std::endl;
	std::cout << "Generating initiator public key:" << _publickey << std::endl;
	std::cout << "Nonce will be sent to responder:" << _nonceI << std::endl;

	// Build IKE header 
	IKEMessage saInitInitatorRequest;
	_ikeSPI = generateSPI(); 
	saInitInitatorRequest.header.initiatorSPI = _ikeSPI;
	_peerSPI = 0; 
	saInitInitatorRequest.header.responderSPI = _peerSPI;
	saInitInitatorRequest.header.nextPayload = static_cast<uint32_t>(PayloadType::KE);
	saInitInitatorRequest.header.majorVersion = 2;
	saInitInitatorRequest.header.minorVersion = 0;
	saInitInitatorRequest.header.exchangeType = static_cast<uint32_t> (IKEExchangeType::SA_INIT);
	saInitInitatorRequest.header.messageID = _messageID;

	// Build IKE payload 
	IKEPayload kePayload = buildKEPayload(_publickey, PayloadType::NONCE);
	IKEPayload  noncePayload = buildNoncePayload(_nonceI, PayloadType::NONE);
	saInitInitatorRequest.payloads.push_back(kePayload);
	saInitInitatorRequest.payloads.push_back(noncePayload);

	// Calculate total IKE message length
	uint32_t totalLength = IKE_HEADER_SIZE;
	for (auto payload : saInitInitatorRequest.payloads)
	{
		totalLength += payload.payloadLength;  
	}

	saInitInitatorRequest.header.length = totalLength;
	std :: vector<uint8_t> binarymessage = saInitInitatorRequest.toByteArray();
	_network.sendPacket(binarymessage);
	_messageID++; 

	std::cout << std::endl;

	return saInitInitatorRequest; 
}

IKEMessage Initiator::processIKE_SA_INIT_Response()
{
	std::cout << "STEP 2 - PROCESS IKE SA INIT RESPONSE" << std::endl;
	std::vector<uint8_t> binaryData = _network.receivePacket();
	IKEMessage saInitResponderResponse;
	saInitResponderResponse.parseIKEmessage(binaryData);

	// Get SPI
	_peerSPI = saInitResponderResponse.header.responderSPI;

	//Get key and nonce 
	std::string ResponderPublicDHKey = binaryToHex(saInitResponderResponse.payloads[0].data);
	InitiatorCrypto::calculateSharedSecret(ResponderPublicDHKey, _privatekey, _sharedSecret);

	std::cout << "Receiving responder public key:" << ResponderPublicDHKey << std::endl; 
	std::cout << "shared Secret:" << _sharedSecret << std::endl;
	_nonceR = binaryToHex(saInitResponderResponse.payloads[1].data);
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

	return saInitResponderResponse; 
}

void Initiator::buildIKE_AUTH(IKEMessage saInitInitatorRequest)
{
	std::cout << "STEP 3 - BUILD IKE AUTH" << std::endl;
	std::cout << std::endl;
	// Build the Identity (IDi) payload using the initiator's identity.
	IKEPayload idPayload = buildIDPayload(_identity, PayloadType::AUTH);
	std::vector<uint8_t> idBytes = idPayload.toByteArray();

	// Build the AUTH payload.
	// InitiatorSignedOctets = IKE_SA_INIT Initator Request + Nr + prf(SK_ai, IDi')
	std::vector<uint8_t> signedOctets;
	std::cout << "//////////// Step 3.1: Performing sign data (Real Message 1 + Nr + prf(SK_ai, IDi') ////////////" << std::endl;
	std::cout << std::endl;
	std::cout << "------------ Real Message 1 (saInitInitatorRequest) ------------" << std::endl; 
	std::cout << std::endl;
	std::vector<uint8_t> realMessage1 = saInitInitatorRequest.toByteArray();
	printHexVector(realMessage1); 
	std::cout << std::endl;

	std::cout << "------------ Nonce R ------------" << std::endl;
	std::cout << std::endl;
	CryptoPP::SecByteBlock nrBytes = hexToSecByteBlock(_nonceR);
	std::vector<uint8_t> Nr(nrBytes.begin(), nrBytes.end());
	printHexVector(Nr);
	std::cout << std::endl;

	std::cout << "------------ prf(SK_ai, IDi') ------------" << std::endl;
	std::cout << std::endl;
	std::string idPayloadWithoutHeader = vectorToString(std::vector<uint8_t>(idPayload.data.begin(), idPayload.data.end()));
	std::string digestStr = InitiatorCrypto::prf(_sk_ai, idPayloadWithoutHeader);
	CryptoPP::SecByteBlock prfOutputBytes = hexToSecByteBlock(digestStr);
	std::vector<uint8_t>  MACedIDForI(prfOutputBytes.begin(), prfOutputBytes.end());
	printHexVector(MACedIDForI);
	std::cout << std::endl;

	signedOctets.insert(signedOctets.end(), realMessage1.begin(), realMessage1.end());
	signedOctets.insert(signedOctets.end(), Nr.begin(), Nr.end());
	signedOctets.insert(signedOctets.end(), MACedIDForI.begin(), MACedIDForI.end());

	// Build the signature using the initiator's private key 
	std::cout << "------------ Data signature using HMAC 256 - 128 ------------" << std::endl;
	std::cout << std::endl;
	std::vector<uint8_t> signature = signData(_sk_ai, signedOctets);
	printHexVector(signature);
	std::cout << std::endl;

	IKEPayload authPayload = buildAuthPayload(signature, PayloadType::NONE);
	std::vector<uint8_t> authBytes = authPayload.toByteArray();

	// Concatenate all payloads: [IDi || AUTH]
	std::cout << "//////////// Step 3.2: Wrap all payloads into Encrypting payload and encrypt IKE message without header (AES-CBC 256) ////////////" << std::endl;
	std::cout << std::endl;

	std::cout << "------------ PLAINTEXT [IDi || AUTH] ------------" << std::endl;
	std::cout << std::endl;
	std::vector<uint8_t> plaintext;
	plaintext.insert(plaintext.end(), idBytes.begin(), idBytes.end());
	plaintext.insert(plaintext.end(), authBytes.begin(), authBytes.end());
	printHexVector(plaintext);
	std::cout << std::endl;

	// Wrap the plaintext into an Encrypted Payload (SK)
	// Use _sk_ei as the AES key 
	std::cout << "------------ CIPHERTEXT [IDi || AUTH] ------------" << std::endl;
	std::cout << std::endl;
	IKEPayload skPayload = buildEncryptedPayload(plaintext, _sk_ei, PayloadType::NONE);
	printHexVector(skPayload.data);
	std::cout << std::endl;

	// Build the outer IKE message
	IKEMessage IKEsaAuthInitiatorRequest;
	IKEsaAuthInitiatorRequest.header.initiatorSPI = _ikeSPI;
	IKEsaAuthInitiatorRequest.header.responderSPI = _peerSPI;

	// The outer message's nextPayload is the type of our single encrypted payload (SK)
	IKEsaAuthInitiatorRequest.header.nextPayload = static_cast<uint8_t>(PayloadType::ENCR);
	IKEsaAuthInitiatorRequest.header.majorVersion = 2;
	IKEsaAuthInitiatorRequest.header.minorVersion = 0;
	IKEsaAuthInitiatorRequest.header.exchangeType = static_cast<uint32_t>(IKEExchangeType::SA_AUTH);
	IKEsaAuthInitiatorRequest.header.messageID = _messageID;

	IKEsaAuthInitiatorRequest.payloads.push_back(skPayload);

	// Calculate the total message length.
	uint32_t totalLength = IKE_HEADER_SIZE;
	for (const auto& p : IKEsaAuthInitiatorRequest.payloads) {
		totalLength += p.payloadLength;
	}
	IKEsaAuthInitiatorRequest.header.length = totalLength;

	// Send the message
	std::vector<uint8_t> binaryMessage = IKEsaAuthInitiatorRequest.toByteArray();
	_network.sendPacket(binaryMessage);
	_messageID++;
}

void Initiator::processIKE_AUTH_Response(IKEMessage saInitResponderResponse)
{
	std::cout << "STEP 4 - Process IKE AUTH" << std::endl;
	std::vector<uint8_t> binaryMessage = _network.receivePacket();

	IKEMessage encryptMsg;
	encryptMsg.parseIKEmessage(binaryMessage);
	IKEPayload encPayload = encryptMsg.payloads[0];

	std::cout << "//////////// Step 4.1: Performing decrypting using AES - CBC 256 ////////////" << std::endl;
	std::cout << std::endl;

	std::cout << "------------ CIPHERTEXT [IDi || AUTH] ------------" << std::endl;
	std::cout << std::endl;
	printHexVector(encPayload.data);
	std::cout << std::endl;

	// Decrypt the SK payload using the Responder's decryption key (_sk_er).
	std::cout << "------------ PLAINTEXT [IDi || AUTH] ------------" << std::endl;
	std::vector<uint8_t> decryptedPayload = parseEncryptedPayload(encPayload, _sk_er);
	std::cout << std::endl;
	printHexVector(decryptedPayload);
	std::cout << std::endl;

	// Parse the inner payloads (IDi ||  AUTH).
	IKEMessage IKEsaAuthInitiatorRequest;
	std::vector<uint8_t> constructedMessage = encryptMsg.header.toByteArray(); // Reconstructing IKEMessage without encrypting payload for the ease of parsing and authenticating
	constructedMessage.insert(constructedMessage.end(), decryptedPayload.begin(), decryptedPayload.end());
	IKEsaAuthInitiatorRequest.parseIKEmessage(constructedMessage);

	// Get identity 
	_peeridentity = vectorToString(IKEsaAuthInitiatorRequest.payloads[0].data);
	std::cout << "Responder identity:" << _peeridentity << std::endl;
	std::cout << std::endl;

	IKEPayload idPayload = IKEsaAuthInitiatorRequest.payloads[0]; // IDi
	IKEPayload authPayload = IKEsaAuthInitiatorRequest.payloads[1]; // AUTH

	std::cout << "//////////// Step 4.2: Performing sign data Real Message 2 + Ni + prf(SK_ar, IDr')  ////////////" << std::endl;
	std::cout << std::endl;

	std::vector<uint8_t> signedOctets;
	std::cout << "------------ Real Message 2 (saInitResponderResponse) ------------" << std::endl;
	std::cout << std::endl;

	std::vector<uint8_t> realMessage2 = saInitResponderResponse.toByteArray();
	printHexVector(realMessage2);
	std::cout << std::endl;

	std::cout << "------------ Nonce I ------------" << std::endl;
	CryptoPP::SecByteBlock niBytes = hexToSecByteBlock(_nonceI);
	std::vector<uint8_t> Ni(niBytes.begin(), niBytes.end());
	printHexVector(Ni);
	std::cout << std::endl;

	std::cout << "------------ prf(SK_ar, IDr') ------------" << std::endl;
	std::cout << std::endl;
	std::string idPayloadWithoutHeader = vectorToString(std::vector<uint8_t>(idPayload.data.begin(), idPayload.data.end()));
	std::string digestStr = InitiatorCrypto::prf(_sk_ar, idPayloadWithoutHeader);
	CryptoPP::SecByteBlock prfOutputBytes = hexToSecByteBlock(digestStr);
	std::vector<uint8_t>  MACedIDForR(prfOutputBytes.begin(), prfOutputBytes.end());
	printHexVector(MACedIDForR);
	std::cout << std::endl;

	signedOctets.insert(signedOctets.end(), realMessage2.begin(), realMessage2.end());
	signedOctets.insert(signedOctets.end(), Ni.begin(), Ni.end());
	signedOctets.insert(signedOctets.end(), MACedIDForR.begin(), MACedIDForR.end());

	std::cout << "------------ Data signature using HMAC 256 - 128 ------------" << std::endl;
	std::cout << std::endl;
	std::vector<uint8_t> expectedAuth = signData(_sk_ar, signedOctets);
	printHexVector(expectedAuth);
	std::cout << std::endl;

	// Verify MAC
	std::cout << "//////////// Step 4.3: COMPARING MAC BETWEEN INITIATOR AND RESPONDER ////////////" << std::endl;
	std::cout << std::endl;
	std::vector<uint8_t> receivedAuth = authPayload.data;
	if (expectedAuth == receivedAuth)
	{
		std::cout << "MAC verification succeeded!" << std::endl;
	}
	else
	{
		std::cerr << "MAC verification failed." << std::endl;
	}

}