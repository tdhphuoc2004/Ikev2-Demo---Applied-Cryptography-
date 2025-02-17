#include "ResponderNetwork.h"
#include "Responder.h"

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
        responder.processIKE_SA_INIT(); 
        system("Pause"); 
    }
    else
    {
        std::cout << "Responder: Connect failed";
        return 0;
    }
  
}
