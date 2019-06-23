#include "../json.hpp"
#include <gmpxx.h>
#include <string>
#ifndef RSA_H
#define RSA_H
namespace Cryptography {
class RSA {
   public:
       mpz_t p, q, // 2 input primal numbers 
       n, // p*q 
       t, // (p-1)(q-1) == pq-q-p+1
       e,
       d;
       mpz_t buf;
       void InitStr(mpz_t& ref, const ::std::string value);
   public:
       static uint32_t Encrypt(uint8_t** dest, const uint8_t* message, const uint64_t size, mpz_t e, mpz_t n);
       uint32_t Decrypt(uint8_t** result, const uint8_t* message);
       RSA(const ::std::string first, const ::std::string second);
       ~RSA();
};
}
#include "RSA.cpp"
#endif