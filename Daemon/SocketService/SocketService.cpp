#include "SocketService.h"

SocketService::SocketService(
    ::std::string DataBaseName,
    bool safeMoneyEnabled,
    uint32_t safeMoneyDelay,
    uint32_t port,
    bool isSharded,
    ::std::string RSA_EFP,
    ::std::string RSA_ESP) {
    this->db = new DataBase(DataBaseName);
     if(isSharded) {
         ::std::cout << "Loading RSA\n";
         this->encrypt = new RSA(RSA_EFP, RSA_ESP);
     }
}