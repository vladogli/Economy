#include <iostream>


#include "SocketService/SocketService.h"
#include <fstream>
#include "json.hpp"

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
        config["sharded"].get<bool>(),
        config["RSA_ENCRYPTION_FIRST_PRIME"].get<::std::string>(),
        config["RSA_ENCRYPTION_SECOND_PRIME"].get<::std::string>());
  //  ss.Join();
}