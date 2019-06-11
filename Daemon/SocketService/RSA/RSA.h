#ifndef RSA_H
#define RSA_H
#include <math.h>
#include <gmpxx.h>
#include <assert.h>
#include <iostream>
namespace RSA_MATH {
    void ExtEuclid(mpz_t ref, mpz_t a, mpz_t b) {
        mpz_t local_a, buf, x, y,
            u, v, gcd, m,
            n, q, r;
        mpz_init(local_a); mpz_init(buf); mpz_init(x); mpz_init(y); 
        mpz_init(u); mpz_init(v); mpz_init(gcd); mpz_init(m); 
        mpz_init(n); mpz_init(q); mpz_init(r);
        
        mpz_set_ui(x, 0); mpz_set_ui(y, 1); 
        mpz_set_ui(u, 1); mpz_set_ui(v, 0);

        mpz_set(local_a, a); mpz_set(gcd,b);

        while(mpz_cmp_ui(local_a, 0) != 0) { // while(local_a != 0)
            mpz_tdiv_q(q,gcd,local_a); // q = gcd / a

            mpz_mod(r,gcd,local_a); // r = gcd % a

            mpz_mul(buf, u, q); mpz_sub(x, m, buf); // m = x - u * q

            mpz_mul(buf, v, q); mpz_sub(n, y, buf); // n = y - v * q

            mpz_set(gcd, a); mpz_set(local_a, r); 
            mpz_set(x, u); mpz_set(y, v);
            mpz_set(u, m); mpz_set(v, n);
        }

        mpz_set(ref, y);
        
        mpz_clear(local_a); mpz_clear(buf); mpz_clear(x); mpz_clear(y); 
        mpz_clear(u); mpz_clear(v); mpz_clear(gcd); mpz_clear(m); 
        mpz_clear(n); mpz_clear(q); mpz_clear(r);
    }
};
class RSA {
    mpz_t p, q, // 2 input primal numbers 
    n, // p*q 
    t, // (p-1)(q-1) == pq-q-p+1
    e,
    d;

    void InitStr(mpz_t& ref, ::std::string value) {
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
    RSA(::std::string first, ::std::string second) {
        InitStr(p,first); InitStr(q,second);

        mpz_mul(n, p, q); // n = p * q

        mpz_init(t);
        mpz_set(t, n); // t = n

        mpz_sub(t, t, q); // t = t - q
        mpz_sub(t, t, p); // t = t - p
        mpz_add_ui(t, t, 1); // t = t + 1

        mpz_init(e);
        mpz_set_ui(e, 3); // e = 0x10001 i.e. 65537

        mpz_init(d);
        ::RSA_MATH::ExtEuclid(d, t, e);
        while(mpz_cmp_ui(d,0) < 0) { // while(d < 0)
            mpz_add(d,d,t); // d = d + n
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
    ~RSA(){
        mpz_clear(p); mpz_clear(q);
        mpz_clear(n); mpz_clear(t);
        mpz_clear(e); mpz_clear(d);
    }
};
#endif