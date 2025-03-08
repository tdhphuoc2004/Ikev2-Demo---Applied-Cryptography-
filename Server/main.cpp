#include "ResponderNetwork.h"
#include "Responder.h"
#include "ResponderIKEHeader.h"
#include "ResponderIKEMessage.h"
#include "ResponderIKEPayload.h"

#include <string>
#include <iostream>
int main() 
{
    ResponderNetwork network("127.0.0.1", 5001);
    network.startListening();
    std::string request = network.receiveTextMessage();
    network.sendTextMessage("Hello IKEv2 Initiator");

    if (request != "ERR")
    {
        Responder responder(network);
        IKEMessage message; 
        std::cout << "===============================" << std::endl;
        std::cout << std::endl;
        responder.processIKE_SA_INIT(message);
        std::cout << "===============================" << std::endl;
        std::cout << std::endl;
        responder.buildIKE_SA_INIT_Response(message);
        std::cout << "===============================" << std::endl;
        std::cout << std::endl;
        responder.processIKE_AUTH(); 
        std::cout << "===============================" << std::endl;
        std::cout << std::endl;
        system("Pause"); 
    }
    else
    {
        std::cout << "Responder: Connect failed";
        return 0;
    }
  
}




