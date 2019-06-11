#ifndef RSA_H
#define RSA_H
#include <math.h>
#include <gmpxx.h>
#include <assert.h>
#include <iostream>
#define __RSA_DEBUG

class RSA {
    mpz_t p, q, // 2 input primal numbers 
    n, // p*q 
    t, // (p-1)(q-1) == pq-q-p+1
    e,
    d;

    void InitStr(mpz_t& ref, const ::std::string value) {
        mpz_init(ref);
        int flag = mpz_set_str(ref,value.c_str(),10);
        if(flag != 0) {
            ::std::cout << "CRITICAL ERROR: RSA Init failed!\n";
            ::std::cout << "Exception in: ::RSA::InitStr(mpz_t& ref, ::std::string value).\n";
            ::std::cout << "Value of value is " <<  value << ::std::endl;
            throw 1;
        }
    }
    
public:
    RSA(const ::std::string first,const ::std::string second) {
        InitStr(p,first); InitStr(q,second);

        mpz_mul(n, p, q); // n = p * q

        mpz_init(t);
        mpz_set(t, n); // t = n

        mpz_sub(t, t, q); // t = t - q
        mpz_sub(t, t, p); // t = t - p
        mpz_add_ui(t, t, 1); // t = t + 1

        mpz_init(e);
        mpz_set_ui(e, 0x10001); // e = 0x10001 i.e. 65537

        mpz_init(d);
        mpz_invert(d, e, t);
        mpz_t buf;
        mpz_init(buf);
        mpz_mul(buf, d,e);
        mpz_tdiv_r(buf,buf,t);
        if(mpz_cmp_ui(buf, 1) != 0) {
            ::std::cout << "RSA CRITICAL ERROR. Something went wrong. Probably problem with primal numbers.";
            throw 1;
        }
        ::std::cout << "RSA was initialized successfully.\nPrimes:\n";
        
        mpz_out_str(stdout, 10, p);
        ::std::cout << ::std::endl;
        mpz_out_str(stdout, 10, q);

        ::std::cout << "\nModulo: ";

        mpz_out_str(stdout, 10, n);

        ::std::cout << "\nResult of Euler function: ";

        mpz_out_str(stdout, 10, t);

        ::std::cout << "\nPrivate Exponent: ";
        mpz_out_str(stdout, 10, d);

        ::std::cout << "\nPublic Exponent: ";
        mpz_out_str(stdout, 10, e);
        std::cout << std::endl;

    }
    void Decrypt(uint8_t* message, const uint64_t size) {
      //
    }
    ~RSA(){
        mpz_clear(p); mpz_clear(q);
        mpz_clear(n); mpz_clear(t);
        mpz_clear(e); mpz_clear(d);
    }
};
#endif