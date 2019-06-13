#ifndef RSA_H
#define RSA_H
#include <math.h>
#include <gmpxx.h>
#include <assert.h>
#include <iostream>
#include "../json.hpp"
#include <string>
#include <random>
#include <fstream> 
#include <sstream>
#include <string>
#include <utility>
#define e 0x10001
namespace Cryptography {
    class RSA {
    public:
        mpz_t p, q, // 2 input primal numbers 
        n, // p*q 
        t, // (p-1)(q-1) == pq-q-p+1
        d;
        mpz_t buf;
        void InitStr(mpz_t& ref, const ::std::string value);
    public:
        static ::std::string Encrypt(const char* message, const uint64_t size, mpz_t n) {
        mpz_t buf;
        if(message == nullptr) {
            throw 0;
        }
        mpz_init(buf);
        ::nlohmann::json j;
        ::std::vector<::std::string> vec;
        for(int i = 0; i < size; i++) {
            mpz_set_ui(buf, message[i]);
            mpz_powm(buf,buf,e,n); 
            mpz_tdiv_r(buf,buf,n);
            char *str = mpz_get_str(nullptr, 62, buf);
            vec.push_back(::std::string(str));
            if(str!=nullptr) {
                free(str);
            }
        }
        j["data"] = vec;
        mpz_clear(buf); 
        return j.dump();
    }
        void Decrypt(char*& result, const ::std::string message);
        RSA(const ::std::string first,const ::std::string second);
        ~RSA();
    };
    namespace SHA {
        namespace Private {
            const uint32_t cbrts[64] = {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            };
            const uint32_t sqrts[8] = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            };
            class sha256 {
            protected:
                typedef unsigned char uint8;
                typedef unsigned int uint32;
                typedef unsigned long long uint64;
                static const unsigned int SHA224_256_BLOCK_SIZE = 64;
            public:
                void init();
                void update(const unsigned char *message, unsigned int len);
                void final(unsigned char *digest);
                static const unsigned int DIGEST_SIZE = 32;
            
            protected:
                void transform(const unsigned char *message, unsigned int block_nb);
                unsigned int m_tot_len;
                unsigned int m_len;
                unsigned char m_block[2*SHA224_256_BLOCK_SIZE];
                uint32 m_h[8];
            };
        }
        uint32_t SHA256(char** dest, char* input, size_t input_size) {
            unsigned char digest[Private::sha256::DIGEST_SIZE];
            memset(digest,0,Private::sha256::DIGEST_SIZE);
        
            Private::sha256 ctx = Private::sha256();
            ctx.init();
            ctx.update( (unsigned char*)input, input_size);
            ctx.final(digest);
        
            char buf[2*Private::sha256::DIGEST_SIZE+1];
            buf[2*Private::sha256::DIGEST_SIZE] = 0;
            for (int i = 0; i < Private::sha256::DIGEST_SIZE; i++)
                sprintf(buf+i*2, "%02x", digest[i]);
            if((*dest) !=nullptr) {
                free(dest);
            }
            (*dest) = (char*)malloc(2*Private::sha256::DIGEST_SIZE+1);
            memcpy((*dest), buf, 2*Private::sha256::DIGEST_SIZE+1);

            return 2*Private::sha256::DIGEST_SIZE+1;
        }
    }

    void GetNoise(char* dest, size_t size);

    // Cryptographycally secure pseudorandom number generator
    class CSPNG {
        char* Noise = nullptr;
        void Load() {
            Noise = (char*)malloc(0x41);
            GetNoise(Noise, 0x41);
        }
        void Unload() {
            free(Noise);
        }
    public:
        void Reload() {
            Unload();
            Load();
        }
        template<typename _T>
        _T get() {
            char* buf = nullptr;
            SHA::SHA256(&buf, Noise, 0x41);
            free(Noise);
            Noise = buf;
            _T returnValue = 0;
            std::stringstream ss;
            unsigned int x;   
            for(int i=0;i<sizeof(_T);i++) {
                ss.clear();
                x = 0;
                ss << std::hex << Noise[i*(0x41/sizeof(_T)) % 0x41] << Noise[i*(0x41/sizeof(_T)) % 0x41 + 1] ;
                ss >> x;
                ((uint8_t*)(&returnValue))[i] = x;
            }
            return returnValue;
        }
        ::std::string getStr() {
            return ::std::string(Noise);
        }
        uint64_t operator()() {
            return get<uint64_t>();
        }
        CSPNG() {
            Load();
        }
        ~CSPNG() {
            Unload();
        }
    };

    
}

#include "Cryptography.cpp"
#endif