#include <iostream>
#include <fstream>
#include "SocketService/SocketService.h"
#include "json.hpp"
#include <string>
#include <chrono>
#define TEST
#ifndef TEST

#define MAIN_CLUSTER
int main() {
    ::std::cout << "Starting\n";
#ifdef MAIN_CLUSTER
    ::std::ifstream configFile("MainCluster.json");
#else
    ::std::ifstream configFile("Cluster.json");
#endif
    ::std::string value="", buf = "";
    while(getline(configFile, buf)) {
        value +=buf + "\n";
    }
    configFile.close();
    auto config = nlohmann::json::parse(value);
#ifdef MAIN_CLUSTER
    SocketService ss(
        config["DBName"].get<::std::string>(),
        config["safeMoney"].get<bool>(),
        config["safeMoneyDelay"].get<uint32_t>(),
        config["port"].get<uint32_t>(),
        config["shardedEconomy"].get<bool>(),
        config["shardedServers"].get<bool>(),
        config["RSA_ENCRYPTION_FIRST_PRIME"].get<::std::string>(),
        config["RSA_ENCRYPTION_SECOND_PRIME"].get<::std::string>()
        config["DSA_ENCRYPTION_3072_PRIME"].get<::std::string>(),
        config["DSA_ENCRYPTION_256_PRIME"].get<::std::string>());
#else
    SocketService ss(
        config["DBName"].get<::std::string>(),
        config["safeMoney"].get<bool>(),
        config["safeMoneyDelay"].get<uint32_t>(),
        config["port"].get<uint32_t>(),
        config["shardedEconomy"].get<bool>(),
        config["DSA_SUB_KEY"].get<::std::string>(),
        config["RSA_PUBLIC_CONSTANT"].get<::std::string>());
#endif
}
#else
#include "test.h"
int main() {
    TestCryptography();
}
#endif




