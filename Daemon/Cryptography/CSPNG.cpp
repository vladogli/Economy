#include "CSPNG.h"
    void Cryptography::GetNoise(uint8_t* dest, size_t size) {
        ::std::system( "/usr/bin/top -b -n 1 | /usr/bin/head -n5 > /tmp/result.txt" );
        ::std::ostringstream oss;
        oss <<  ::std::ifstream("/tmp/result.txt").rdbuf();
        ::std::string a = oss.str();
        for(auto i = a.begin();i!=a.end();i++) {
            if(!((*i) > '0' && (*i) <= '9')) {
                auto saved = i;
                if(i!=a.begin()) {i--;}
                a.erase(saved);
            }
        }
        if(a.size() < size) {
            memcpy(dest,a.c_str(), a.size());
        } else {
            memcpy(dest,a.c_str(), size);   
        }
    }
    void ::Cryptography::CSPNG::Load() {
        Noise = (uint8_t*)malloc(0x41);
        GetNoise(Noise, 0x41);
    }
    void ::Cryptography::CSPNG::Unload() {
        free(Noise);
    }
    void ::Cryptography::CSPNG::Reload() {
        Unload();
        Load();
    }
    template<typename _T>
    _T Cryptography::CSPNG::get() {
        uint8_t* buf = nullptr;
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
    ::std::string Cryptography::CSPNG::getStr() {
        uint8_t* buf = nullptr;
        SHA::SHA256(&buf, Noise, 0x41);
        free(Noise);
        Noise = buf;
        return ::std::string((char*)(Noise));
    }
    uint32_t ::Cryptography::CSPNG::operator()() {
        return get<uint32_t>();
    }
    ::Cryptography::CSPNG::CSPNG() {
        Load();
    }
    ::Cryptography::CSPNG::~CSPNG() {
        Unload();
    }
