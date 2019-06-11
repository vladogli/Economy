#ifndef SOCKET_SERVICE_H
#define SOCKET_SERVICE_H
#include <sys/types.h>
#include <sys/socket.h>
#include "../DataBase/DataBase.h"
#include "RSA/RSA.h"
class SocketService {
    DataBase *db = nullptr;
    RSA *encrypt = nullptr;
public:
SocketService(
    ::std::string, bool,
    uint32_t, uint32_t,
    bool, bool,
    ::std::string,
    ::std::string);
};
#include "SocketService.cpp"
#endif