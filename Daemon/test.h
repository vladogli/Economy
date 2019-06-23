#include "Cryptography/includes.h"
#include <iostream>
std::string V = "testtesttesttest";
using namespace Cryptography;
using namespace SHA;
using namespace AES;
void TestSHA() {
    uint8_t *out = nullptr;
    uint8_t *input = (uint8_t*)V.c_str();
    size_t outLen = SHA256(&out, input, V.size());
    if(std::string((char*)out)!="5e8b64da785f1572e6da780648eaaffa009152d297bde80f852f068b0ec2989f") {
        std::cout << "Test failed(SHA256)\n";
    }
    free(out);
}
void TestAES() {
std::string key = "akldhkasdhjkldwj";
    uint8_t *out = nullptr;
    uint8_t *decrypted = nullptr;
    uint32_t outLen;
    CSPNG cspng;
    out = EncryptECB((uint8_t*)V.c_str(), V.size(), (uint8_t*)key.c_str(), outLen);
    decrypted = DecryptECB(out, outLen, (uint8_t*)key.c_str(), outLen);
    if(std::string((char*)decrypted)!=V && 4 != outLen) {
        std::cout << "Test failed(AES::EncryptECB)\n";
        std::cout << std::string((char*)decrypted) << std::endl;
    } 
    free(out);
    free(decrypted);

std::string initVector = cspng.getStr();

    out = EncryptCBC((uint8_t*)V.c_str(), V.size(), (uint8_t*)key.c_str(), (uint8_t*)initVector.c_str(), outLen);
    decrypted = DecryptCBC(out, outLen, (uint8_t*)key.c_str(),(uint8_t*)initVector.c_str(), outLen);
    if(std::string((char*)decrypted)!=V && V.size() != outLen) {
        std::cout << "Test failed(AES::EncryptCBC)\n";
        std::cout << std::string((char*)decrypted) << std::endl;
    } 
    free(out);
    free(decrypted);

    out = EncryptCFB((uint8_t*)V.c_str(), V.size(), (uint8_t*)key.c_str(), (uint8_t*)initVector.c_str(), outLen);
    decrypted = DecryptCFB(out, outLen, (uint8_t*)key.c_str(),(uint8_t*)initVector.c_str(), outLen);
    if(std::string((char*)decrypted)!=V && V.size() != outLen) {
        std::cout << "Test failed(AES::EncryptCFB)\n";
        std::cout << std::string((char*)decrypted) << std::endl;
    } 
    free(out);
    free(decrypted);
}
void TestDES() {

}
void TestRSA() {
    RSA rsa("166850656532068681262183508203914970745841887028305106991099018794320129635497797467937827100010263377666947688901480971770725230649145210720867446152806211627255627224923946078848310769423051561826651249895005242021839967222820139976590080986361533554551420530749302208708380976958561017992913493117117410531", 
        "124019524078731792072251776700433124378968521802687392622651805811010927358637234634148456273772361944726552092668658720644389451465584236607979458245806091178138064106779276756535363633827342667654147358820511101307523748378706105917036570502575034596986751003341615671848903014273491298174163034681711920743");
    uint8_t *encrypted;
    size_t size = RSA::Encrypt(&encrypted, (uint8_t*)V.c_str(), V.size(), rsa.e, rsa.n);
    uint8_t *decrypted;
    size_t size2 = rsa.Decrypt(&decrypted, encrypted);
    if(std::string((char*)decrypted)!=V) {
        std::cout << "Test failed(RSA Encryption)\n";
        std::cout << std::string((char*)decrypted) << std::endl;
    }
    free(encrypted);
    free(decrypted);
}
void TestCryptography() {
    TestSHA();
    TestAES();
    TestDES();
    TestRSA();
}