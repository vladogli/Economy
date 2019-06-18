#include <iostream>
#include <fstream>
#include "SocketService/SocketService.h"
#include "json.hpp"
#include <string>
int main() {
    ::std::cout << "Starting\n";
    ::std::ifstream configFile("config.json");
    ::std::string value="", buf = "";
    while(getline(configFile, buf)) {
        value +=buf + "\n";
    }
    configFile.close();
    auto config = nlohmann::json::parse(value);
//    SocketService ss(
//        config["DBName"].get<::std::string>(),
 //       config["safeMoney"].get<bool>(),
  //      config["safeMoneyDelay"].get<uint32_t>(),
   //     config["port"].get<uint32_t>(),
    //    config["shardedEconomy"].get<bool>(),
     //   config["shardedServers"].get<bool>(),
      //  config["RSA_ENCRYPTION_FIRST_PRIME"].get<::std::string>(),
       // config["RSA_ENCRYPTION_SECOND_PRIME"].get<::std::string>());
using namespace Cryptography;
using namespace AES;
    char* out;
    char* out2;
    ::std::string in = "abcdef";
    ::std::string key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for(int i=0;i<in.size();i++) {
        std::cout << int16_t(in.c_str()[i])  << " ";
    }
    std::cout << std::endl;
    auto len = Encrypt(in.c_str(),6,&out,key.c_str());
    for(int i=0;i<len;i++) {
        std::cout << int16_t(out[i])  << " ";
    }
    std::cout << std::endl;
    Decrypt(out, len, &out2, key.c_str());
    for(int i=0;i<len;i++) {
        std::cout << int16_t(out2[i])  << " ";
    }
    free(out);
    free(out2);
}




