#ifndef CSPNG_H
#define CSPNG_H
#include "SHA.h"
#include <sstream>
#include <fstream>
namespace Cryptography {
    void GetNoise(char* dest, size_t size);
    // Cryptographycally secure pseudorandom number generator
    class CSPNG {
        char* Noise = nullptr;
        void Load();
        void Unload();
    public:
        void Reload();
        template<typename _T>
        _T get();
        ::std::string getStr();
        uint32_t operator()();
        CSPNG();
        ~CSPNG();
    };
}
#include "CSPNG.cpp"
#endif