#include "RSA.h"

#define E 0x10001
    void ::Cryptography::RSA::InitStr(mpz_t& ref, const ::std::string value) {
            mpz_init(ref);
            int flag = mpz_set_str(ref,value.c_str(),10);
            if(flag != 0) {
                ::std::cout << "CRITICAL ERROR: RSA Init failed!\n";
                ::std::cout << "Exception in: ::Cryptography::RSA::InitStr(mpz_t& ref, ::std::string value).\n";
                ::std::cout << "Value of value is " <<  value << ::std::endl;
                throw 1;
            }
    }
    ::Cryptography::RSA::RSA(const ::std::string first,const ::std::string second) {
            InitStr(p,first); InitStr(q,second);
            mpz_mul(n, p, q); // n = p * q

            mpz_init(e);
            mpz_set_ui(e, E);

            mpz_init(t);
            mpz_set(t, n); // t = n

            mpz_sub(t, t, q); // t = t - q
            mpz_sub(t, t, p); // t = t - p
            mpz_add_ui(t, t, 1); // t = t + 1

            mpz_init(d);
            mpz_invert(d, e, t);

            mpz_init(buf);
            mpz_mul(buf, d,e);
            mpz_tdiv_r(buf,buf,t);

            if(mpz_cmp_ui(buf, 1) != 0) {
                ::std::cout << "RSA CRITICAL ERROR. Something went wrong. Probably problem with primal numbers.";
                throw 1;
            }

    }
    ::Cryptography::RSA::~RSA(){
            mpz_clear(p); mpz_clear(q);
            mpz_clear(n); mpz_clear(t);
            mpz_clear(e); mpz_clear(d);
            mpz_clear(buf);
    }
    size_t approxLog2(mpz_t v) {
        mpz_t buf, b;
        mpz_init(buf); mpz_init(b);
        mpz_set(buf, v); mpz_set_ui(b, 2);
        size_t itr = 0;
        while(mpz_cmp_ui(buf, 1) > 0) {
            mpz_tdiv_q(buf,buf,b);
            itr++;
        }
        mpz_clear(buf);
        mpz_clear(b);
        return itr;
    }
#define DEC_TO_HEX(x) ((x >= 10) ? ('a' + x - 10) : ('0' + x))
#define HEX_TO_DEC(x) ((x >= 'a') ? (x - 'a') : (x - '0'))
                        
                        
    void TransformTo0x10From0x100(uint8_t* dest, uint8_t* from, size_t log2OfModulo) {
        uint32_t len = strlen((char*)from);
        if(len>log2OfModulo) {
            len = log2OfModulo;
        }
        memset(dest, 0, log2OfModulo);
        for(size_t i = 0; i < len; i++) {
            if(from[i] == 0) {
                break;
            }
            dest[2 * i] = DEC_TO_HEX(from[i] / 0x10);
            dest[2 * i + 1] = DEC_TO_HEX(from[i] % 0x10);
        }
    }
    void TransformTo0x100From0x10(uint8_t* dest, uint8_t* from, size_t log2OfModulo) {
        uint32_t len = strlen((char*)from)/2;
        if(len>log2OfModulo) {
            len = log2OfModulo;
        }
        memset(dest, 0, log2OfModulo);
        for(size_t i = 0; i < len; i++) {
            if(from[2 * i] == 0 && from[2 * i + 1] == 0) {
                break;
            }
            dest[i] = HEX_TO_DEC(from[2 * i]) * 0x10 + HEX_TO_DEC(from[2 * i + 1]);
        }
    }
    uint32_t Cryptography::RSA::Encrypt(uint8_t** dest, const uint8_t* message, const uint64_t size, mpz_t publicExponent, mpz_t modulo) {
        mpz_t buf;
        if(message == nullptr || dest == nullptr || (*dest)!=nullptr) {
            throw 0;
        }
        mpz_init(buf);
        ::nlohmann::json j;
        ::std::vector<::std::string> vec;
        
        size_t log2OfModulo = (approxLog2(modulo) - 1)/16;

        uint8_t *buffer = (uint8_t*)malloc(log2OfModulo+1);
        uint8_t *hexTransformedBuffer = (uint8_t*)malloc(2*log2OfModulo+1);
        memset(hexTransformedBuffer, 0, 2*log2OfModulo+1);
        buffer[log2OfModulo] = 0;
        
        for(size_t i = 0; i < size; i += log2OfModulo) {
            if((int64_t(size) - i) > log2OfModulo) {
                memcpy(buffer, message + i, log2OfModulo);
            } else {
                memcpy(buffer, message + i, size-i);
                buffer[size-i] = 0;
            }
            TransformTo0x10From0x100(hexTransformedBuffer, buffer, log2OfModulo);
            mpz_set_str(buf, (char*)hexTransformedBuffer, 0x10);
            mpz_powm(buf, buf, publicExponent,modulo); 
            mpz_tdiv_r(buf, buf, modulo);
            char *str = mpz_get_str(nullptr, 62, buf);
            vec.push_back(::std::string(str));
            free(str);
        }
        j["data"] = vec;
        mpz_clear(buf);
        free(buffer);
        free(hexTransformedBuffer);
        std::string v = j.dump();
        (*dest) = (uint8_t*)malloc(v.size()+1);
        (*dest)[v.size()] = 0;
        memcpy((*dest), v.c_str(), v.size());
        
        return v.size()+1;
   }
   uint32_t ::Cryptography::RSA::Decrypt(uint8_t **result, const uint8_t*  message) {
        nlohmann::json j = nlohmann::json::parse(std::string((char*)message));
        size_t size = j["data"].size();
        if(result == nullptr || (*result) != nullptr) {
            throw 1;
        }
        size_t log2OfModulo = (approxLog2(n) - 1)/16;

        uint32_t resultSize = log2OfModulo*size;
        (*result) = (uint8_t*)malloc(resultSize*sizeof(uint8_t));
        memset((*result), 0, resultSize);
        uint8_t *buffer = (uint8_t*)malloc(log2OfModulo);

        for(size_t i = 0; i < size; i++) {
            ::std::string str = j["data"][i].get<::std::string>();
            mpz_set_str(buf, str.c_str(), 62);
            mpz_powm(buf, buf, d, n);
            mpz_tdiv_r(buf, buf, n);
            uint8_t *hexTransformedBuffer = (uint8_t*)mpz_get_str(nullptr, 0x10, buf);
            TransformTo0x100From0x10(buffer, hexTransformedBuffer, log2OfModulo);
            memcpy((*result) + i*log2OfModulo, buffer, log2OfModulo);
            free(hexTransformedBuffer);
        }
        free(buffer);
        for(size_t i=0;i<resultSize;i++) {
            if((*result)[i] == 0) {
                void *ptr = realloc((*result), i+1);
                if(ptr!=nullptr) {
                    (*result) = (uint8_t*) ptr;
                }
                break;
            }
        }
        return resultSize;
    }
#undef E