#include "Responder.h"
#include "ResponderIKEHeader.h"
#include "ResponderIKEMessage.h"
#include "ResponderIKEPayload.h"
#include "ResponderCrypto.h"
#include "ResponderAuth.h"
#include "Utils.h"
#include "ResponderNetwork.h"

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>


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

IKEMessage Responder::processIKE_SA_INIT()
{
    std::cout << "STEP 1 - PROCESS IKE SA INIT" << std::endl; 
	std::vector<uint8_t> binaryData = _network.receivePacket(); 
    IKEMessage saInitInitatorRequest;
	// Parsing packet first
    saInitInitatorRequest.parseIKEmessage(binaryData);
    _peerSPI = saInitInitatorRequest.header.initiatorSPI; // Copy from initiator request
    _messageID = saInitInitatorRequest.header.messageID; 
	// Getting Key and Nonce 
	std::string InitiatorDHKey = binaryToHex(saInitInitatorRequest.payloads[0].data);
	ResponderCrypto::generateDHKey(_privatekey, _publickey);

	std::cout << "Generating responder private key:" << _privatekey << std::endl;
	std::cout << "Generating responder public key:" << _publickey << std::endl;
    std::cout << "Receiving initiator public key:" << InitiatorDHKey << std::endl;

	ResponderCrypto::calculateSharedSecret(InitiatorDHKey, _privatekey, _sharedSecret);
	std::cout << "Shared Secret:" << _sharedSecret << std::endl; 

	_nonceI = binaryToHex(saInitInitatorRequest.payloads[1].data);
    std::cout << "Nonce from initator:" << _nonceI <<  std::endl;

    std::cout << std::endl;

    return saInitInitatorRequest; 
}

IKEMessage Responder::buildIKE_SA_INIT_Response()
{
    std::cout << "STEP 2 - SA IKE INIT RESPONSE" << std::endl;
    IKEMessage saInitResponderResponse;
    // Set Up IKE Header
    saInitResponderResponse.header.initiatorSPI = _peerSPI;
    _ikeSPI = generateSPI();
    saInitResponderResponse.header.responderSPI = _ikeSPI;
    saInitResponderResponse.header.nextPayload = static_cast<uint8_t> (PayloadType::KE);
    saInitResponderResponse.header.minorVersion = 0;
    saInitResponderResponse.header.exchangeType = static_cast<uint8_t> (IKEExchangeType::SA_INIT);
    saInitResponderResponse.header.messageID = _messageID;

    // Build KE Payload 
    IKEPayload kePayload = buildKEPayload(_publickey, PayloadType::NONCE);

    // Build Nonce payload 
    ResponderCrypto::generateNonce(_nonceR); 
    std::cout << "Nonce will be sent to initator:" << _nonceR << std::endl;
    std::cout << "Responder public key will be sent to Initiator:" << _publickey << std::endl;
    IKEPayload noncePayload = buildNoncePayload(_nonceR, PayloadType::CERTREQ);

    saInitResponderResponse.payloads.push_back(kePayload);
    saInitResponderResponse.payloads.push_back(noncePayload);

    // Calculate total IKE message length
    uint32_t totalLength = IKE_HEADER_SIZE;
    for (auto payload : saInitResponderResponse.payloads)
    {
        totalLength += payload.payloadLength;
    }

    saInitResponderResponse.header.length = totalLength;

    // Send it 
    std::vector<uint8_t> binarymessage = saInitResponderResponse.toByteArray();
    _network.sendPacket(binarymessage);

    // Calculating SKEYSEED
    std::cout << std::endl;
    std::cout << "------------CALCULATING KEY MATERIALS------------" << std::endl; 
    _skeyseed = ResponderCrypto::generateSKEYSEED(_sharedSecret, _nonceI, _nonceR);
    std::cout << "Skeyseed:" << _skeyseed << std::endl;

    // Deriving keys 
    ResponderCrypto::deriveKeys(_skeyseed, _nonceI, _nonceR, _peerSPI, _ikeSPI, _sk_d, _sk_ai, _sk_ar, _sk_ei, _sk_er);
    std::cout << "Key child SA:" << _sk_d << std::endl;
    std::cout << "Key auth initiator:" << _sk_ai << std::endl;
    std::cout << "Key auth responder:" << _sk_ar << std::endl;
    std::cout << "Key encrypt initiator:" << _sk_ei << std::endl;
    std::cout << "Key encrypt responder:" << _sk_er << std::endl;

    std::cout << std::endl;

    return saInitResponderResponse; 
}

void Responder::processIKE_AUTH(IKEMessage saInitInitatorRequest)
{
    std::cout << "STEP 3 - PROCESS IKE AUTH" << std::endl;
    std::cout << std::endl;
    std::vector<uint8_t> binaryMessage = _network.receivePacket();

    IKEMessage encryptMsg;
    encryptMsg.parseIKEmessage(binaryMessage);
    IKEPayload encPayload = encryptMsg.payloads[0];

    std::cout << "//////////// Step 3.1: Performing decrypting using AES - CBC 256 ////////////" << std::endl;
    std::cout << std::endl;

    std::cout << "------------ CIPHERTEXT [IDi || AUTH] ------------" << std::endl;
    std::cout << std::endl;
    printHexVector(encPayload.data);
    std::cout << std::endl;

    // Decrypt the SK payload using the initiator's decryption key (_sk_ei).
    std::cout << "------------ PLAINTEXT [IDi || AUTH] ------------" << std::endl;
    std::vector<uint8_t> decryptedPayload = parseEncryptedPayload(encPayload, _sk_ei);
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
    std::cout << "Initiator identity:" << _peeridentity << std::endl;
    std::cout << std::endl; 

    IKEPayload idPayload = IKEsaAuthInitiatorRequest.payloads[0]; // IDi
    IKEPayload authPayload = IKEsaAuthInitiatorRequest.payloads[1]; // AUTH

    std::cout << "//////////// Step 3.2: Performing sign data (Real Message 1 + Nr + prf(SK_ai, IDi') ////////////" << std::endl;
    std::cout << std::endl;

    std::vector<uint8_t> signedOctets;
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
    std::string digestStr = ResponderCrypto::prf(_sk_ai, idPayloadWithoutHeader);
    CryptoPP::SecByteBlock prfOutputBytes = hexToSecByteBlock(digestStr);
    std::vector<uint8_t>  MACedIDForI(prfOutputBytes.begin(), prfOutputBytes.end());
    printHexVector(MACedIDForI);
    std::cout << std::endl;

    signedOctets.insert(signedOctets.end(), realMessage1.begin(), realMessage1.end());
    signedOctets.insert(signedOctets.end(), Nr.begin(), Nr.end());
    signedOctets.insert(signedOctets.end(), MACedIDForI.begin(), MACedIDForI.end());

    std::cout << "------------ Data signature using HMAC 256 - 128 ------------" << std::endl;
    std::cout << std::endl;
    std::vector<uint8_t> expectedAuth = signData(_sk_ai, signedOctets);
    printHexVector(expectedAuth);
    std::cout << std::endl;

    // Verify MAC
    std::cout << "//////////// Step 3.3: COMPARING MAC BETWEEN INITIATOR AND RESPONDER ////////////" << std::endl;
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
    
    std::cout << std::endl;
}

void Responder::buildIKE_AUTH_Response(IKEMessage saInitResponderResponse)
{
    std::cout << "STEP 4 - BUILD IKE AUTH" << std::endl;
    std::cout << std::endl;

    // Build the Identity (IDi) payload using the Responder's identity.
    IKEPayload idPayload = buildIDPayload(_identity, PayloadType::AUTH);
    std::vector<uint8_t> idBytes = idPayload.toByteArray();

    // Build the AUTH payload.
    // ResponderSignedOctets = IKE_SA_INIT Responder Response + Ni + prf(SK_ar, IDr')
    std::vector<uint8_t> signedOctets;

    std::cout << "//////////// Step 4.1: Performing sign data (Real Message 2 + Ni + prf(SK_ar, IDr') ////////////" << std::endl;
    std::cout << std::endl;
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
    std::string digestStr = ResponderCrypto::prf(_sk_ar, idPayloadWithoutHeader);
    CryptoPP::SecByteBlock prfOutputBytes = hexToSecByteBlock(digestStr);
    std::vector<uint8_t>  MACedIDForR(prfOutputBytes.begin(), prfOutputBytes.end());
    printHexVector(MACedIDForR);
    std::cout << std::endl;

    signedOctets.insert(signedOctets.end(), realMessage2.begin(), realMessage2.end());
    signedOctets.insert(signedOctets.end(), Ni.begin(), Ni.end());
    signedOctets.insert(signedOctets.end(), MACedIDForR.begin(), MACedIDForR.end());

    // Build the signature using the responder's private key 
    std::cout << "------------ Data signature using HMAC 256 - 128 ------------" << std::endl;
    std::cout << std::endl;
    std::vector<uint8_t> signature = signData(_sk_ar, signedOctets);
    printHexVector(signature);
    std::cout << std::endl;

    IKEPayload authPayload = buildAuthPayload(signature, PayloadType::NONE);
    std::vector<uint8_t> authBytes = authPayload.toByteArray();

    // Concatenate all payloads: [IDi || AUTH]
    std::cout << "//////////// Step 4.2: Wrap all payloads into Encrypting payload and encrypt IKE message without header (AES-CBC 256) ////////////" << std::endl;
    std::cout << std::endl;

    std::cout << "------------ PLAINTEXT [IDi || AUTH] ------------" << std::endl;
    std::cout << std::endl;
    std::vector<uint8_t> plaintext;
    plaintext.insert(plaintext.end(), idBytes.begin(), idBytes.end());
    plaintext.insert(plaintext.end(), authBytes.begin(), authBytes.end());
    printHexVector(plaintext);
    std::cout << std::endl;

    // Wrap the plaintext into an Encrypted Payload (SK)
    // Use _sk_er as the AES key 
    std::cout << "------------ CIPHERTEXT [IDi || AUTH] ------------" << std::endl;
    std::cout << std::endl;
    IKEPayload skPayload = buildEncryptedPayload(plaintext, _sk_er, PayloadType::NONE);
    printHexVector(skPayload.data);
    std::cout << std::endl;

    IKEMessage IKEsaAuthResponderResponse;
    IKEsaAuthResponderResponse.header.initiatorSPI = _peerSPI;
    IKEsaAuthResponderResponse.header.responderSPI = _ikeSPI;
    IKEsaAuthResponderResponse.header.nextPayload = static_cast<uint8_t>(PayloadType::ENCR);
    IKEsaAuthResponderResponse.header.majorVersion = 2;
    IKEsaAuthResponderResponse.header.minorVersion = 0;
    IKEsaAuthResponderResponse.header.exchangeType = static_cast<uint8_t>(IKEExchangeType::SA_AUTH);
    IKEsaAuthResponderResponse.header.messageID = _messageID;

    IKEsaAuthResponderResponse.payloads.push_back(skPayload);

    // Calculate the total message length.
    uint32_t totalLength = IKE_HEADER_SIZE;
    for (const auto& p : IKEsaAuthResponderResponse.payloads)
    {
        totalLength += p.payloadLength;
    }
    IKEsaAuthResponderResponse.header.length = totalLength;

    std::vector<uint8_t> binaryMessage = IKEsaAuthResponderResponse.toByteArray();
    _network.sendPacket(binaryMessage);

}
