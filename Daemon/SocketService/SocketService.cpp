#include "SocketService.h"

SocketService::SocketService(
    ::std::string DataBaseName,
    bool safeMoneyEnabled,
    uint32_t safeMoneyDelay,
    uint32_t port,
    bool isShardedEconomy, bool isShardedServers,
    ::std::string RSA_EFP,
    ::std::string RSA_ESP) {
    this->db = new DataBase(DataBaseName);
     if(isShardedServers) {
         ::std::cout << "Loading RSA\n";
         this->rsa = new ::Cryptography::RSA(RSA_EFP, RSA_ESP);
     }
}