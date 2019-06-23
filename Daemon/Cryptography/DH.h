#include <gmpxx.h>
#include <string>
#ifndef DH
#define DH
namespace Cryptography {
    namespace DH {
        mpz_t G, P;
        void load(::std::string g, ::std::string p) {
            mpz_set_str(G, g.c_str(), 10);
            mpz_set_str(P, p.c_str(), 10);
        } 
        
        struct Connection {
            mpz_t a;
            mpz_t A;
            mpz_t K;
            Connection(::std::string g, ::std::string p){
                load(g, p);
                Connection();
            }
            Connection() {
                mpz_init(a); mpz_init(A); mpz_init(K);
                CSPNG r;
                ::std::string v = r.getStr() + r.getStr() + r.getStr() + r.getStr();
                mpz_set_str(a, v.c_str(), 0x10);
                mpz_powm(A,G,a,P);
            }
            void ReloadSecretKey(::std::string B) {
                mpz_set_str(K, B.c_str(), 66);
                mpz_powm(K,K,a,P);
            }
            ~Connection() {
                mpz_clear(a); mpz_clear(A); mpz_clear(K);
            }
        };
    }
}
#endif