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
       static ::std::string Encrypt(const char* message, const uint64_t size, mpz_t e, mpz_t n);
       void Decrypt(char*& result, const ::std::string message);
       RSA(const ::std::string first,const ::std::string second);
       ~RSA();
};
}
#include "RSA.cpp"
#endif