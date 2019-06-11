#ifndef RSA_H
#define RSA_H
#include <math.h>
#include <gmpxx.h>
#include <assert.h>
#include <iostream>
#include "../json.hpp"
#include <string>
#define __RSA_DEBUG

class RSA {
    mpz_t p, q, // 2 input primal numbers 
    n, // p*q 
    t, // (p-1)(q-1) == pq-q-p+1
    e,
    d;
    mpz_t buf;
    void InitStr(mpz_t& ref, const ::std::string value);
public:
    RSA(const ::std::string first,const ::std::string second);
    ::std::string Encrypt(const char *message, const uint64_t size);
    void Decrypt(char *&result, const ::std::string message);
    ~RSA();
};
#include "Cryptography.cpp"
#endif