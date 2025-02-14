#include "ResponderNetwork.h"
#include "Responder.h"

#include <string>
#include <iostream>
int main() 
{
    ResponderNetwork network("127.0.0.1", 5001);
    network.startListening();
    std::string request = network.receivePacket();
    network.sendPacket("Hello IKEv2 Initiator");

    if (request != "ERR")
    {
        Responder responder(network);
        system("Pause");
    }
    else
    {
        std::cout << "Responder: Connect failed";
        return 0;
    }
  
}
