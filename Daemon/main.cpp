#include <iostream>


#include "SocketService/SocketService.h"
#include <fstream>
#include "json.hpp"
#include <string>
int main() {
    ::std::cout << "Starting...\n";
    ::std::ifstream configFile("config.json");
    ::std::string value="", buf = "";
    while(getline(configFile, buf)) {
        value +=buf + "\n";
    }
    configFile.close();
    auto config = nlohmann::json::parse(value);
    SocketService ss(
        config["DBName"].get<::std::string>(),
        config["safeMoney"].get<bool>(),
        config["safeMoneyDelay"].get<uint32_t>(),
        config["port"].get<uint32_t>(),
        config["shardedEconomy"].get<bool>(),
        config["shardedServers"].get<bool>(),
        config["RSA_ENCRYPTION_FIRST_PRIME"].get<::std::string>(),
        config["RSA_ENCRYPTION_SECOND_PRIME"].get<::std::string>());
    std::string encrypted;
    ::std::string input;
    ::std::cout << "Enter your message: ";
    ::std::cin >> input;
    encrypted = ss.rsa->Encrypt(input.c_str(), input.size());

    char* decrypted;
    ::std::cout << "Encrypted message: ";
    std::cout <<encrypted << ::std::endl;

    ss.rsa->Decrypt(decrypted, encrypted);
    
    ::std::cout << "Decrypted message: " << ::std::string(decrypted) << std::endl;
} 