#ifndef SOCKET_SERVICE_H
#define SOCKET_SERVICE_H
#include <sys/types.h>
#include <sys/socket.h>
#include "../DataBase/DataBase.h"
#include "Cryptography.h"
class SocketService {
public:
    DataBase *db = nullptr;
    RSA *rsa = nullptr;
SocketService(
    ::std::string, bool,
    uint32_t, uint32_t,
    bool, bool,
    ::std::string,
    ::std::string);
};
#include "SocketService.cpp"
#endif