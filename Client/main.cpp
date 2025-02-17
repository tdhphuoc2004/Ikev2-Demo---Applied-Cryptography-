#include "InitiatorNetwork.h"
#include "Initiator.h"
int main() 
{
    InitiatorNetwork network("127.0.0.1", 5001);
    network.connectToResponder();
    network.sendTextMessage("Hello IKEv2 Responder");
    std::string response = network.receiveTextMessage();

    if (response != "ERR")
    {
        Initiator initiator(network); 
        initiator.buildIKE_SA_INIT(); 
        
    }
    else
    {
        std::cout << "Initiator: Connect failed"; 
        return 0; 
    }
}
