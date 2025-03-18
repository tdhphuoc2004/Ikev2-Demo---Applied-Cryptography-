#include "InitiatorNetwork.h"
#include "Initiator.h"
#include "InitiatorIKEmessage.h"

int main() 
{
    InitiatorNetwork network("127.0.0.1", 5001);
    network.connectToResponder();
    network.sendTextMessage("Hello IKEv2 Responder");
    std::string response = network.receiveTextMessage();

    if (response != "ERR")
    {
        IKEMessage message; 
        Initiator initiator(network); 
        std::cout << "===============================" << std::endl;
        std::cout << std::endl; 
        initiator.buildIKE_SA_INIT(); 
        std::cout << "===============================" << std::endl;
        std::cout << std::endl;
        initiator.processIKE_SA_INIT_Response(message); 
        std::cout << "===============================" << std::endl;
        std::cout << std::endl;
        initiator.buildIKE_AUTH(message); 
        std::cout << "===============================" << std::endl;
        std::cout << std::endl;
    }
    else
    {
        std::cout << "Initiator: Connect failed"; 
        return 0; 
    }
}


