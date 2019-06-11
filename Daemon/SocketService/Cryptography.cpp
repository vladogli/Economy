#include "Cryptography.h"
void RSA::InitStr(mpz_t& ref, const ::std::string value) {
        mpz_init(ref);
        int flag = mpz_set_str(ref,value.c_str(),10);
        if(flag != 0) {
            ::std::cout << "CRITICAL ERROR: RSA Init failed!\n";
            ::std::cout << "Exception in: ::RSA::InitStr(mpz_t& ref, ::std::string value).\n";
            ::std::cout << "Value of value is " <<  value << ::std::endl;
            throw 1;
        }
    }

RSA::RSA(const ::std::string first,const ::std::string second) {
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
        ::std::cout << ::std::endl;

}
::std::string RSA::Encrypt(const char *message, const uint64_t size) {
        if(message == nullptr) {
            throw 0;
        }
        nlohmann::json j;
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
        return j.dump();
    }
void RSA::Decrypt(char *&result, const ::std::string message) {
        nlohmann::json j = nlohmann::json::parse(message);
        size_t size = j["data"].size();
        result = (char*)malloc((size+1)*sizeof(char));
        if(result == nullptr) {
            throw 1;
        }
        for(int i = 0; i < size; i++) {
            ::std::string str = j["data"][i].get<::std::string>();
            mpz_set_str(buf, str.c_str(),62);
            mpz_powm(buf,buf,d,n);
            result[i] = mpz_get_ui(buf);
        }
        result[size] = '\0';
    }
RSA::~RSA(){
        mpz_clear(p); mpz_clear(q);
        mpz_clear(n); mpz_clear(t);
        mpz_clear(e); mpz_clear(d);
        mpz_clear(buf);
}