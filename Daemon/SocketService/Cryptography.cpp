#include "Cryptography.h"
void ::Cryptography::RSA::InitStr(mpz_t& ref, const ::std::string value) {
        mpz_init(ref);
        int flag = mpz_set_str(ref,value.c_str(),10);
        if(flag != 0) {
            ::std::cout << "CRITICAL ERROR: RSA Init failed!\n";
            ::std::cout << "Exception in: ::RSA::InitStr(mpz_t& ref, ::std::string value).\n";
            ::std::cout << "Value of value is " <<  value << ::std::endl;
            throw 1;
        }
    }



void ::Cryptography::RSA::Decrypt(char *&result, const ::std::string message) {
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
::Cryptography::RSA::RSA(const ::std::string first,const ::std::string second) {
        InitStr(p,first); InitStr(q,second);
        mpz_mul(n, p, q); // n = p * q

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
::Cryptography::RSA::~RSA(){
        mpz_clear(p); mpz_clear(q);
        mpz_clear(n); mpz_clear(t);
        mpz_clear(e); mpz_clear(d);
        mpz_clear(buf);
}

void ::Cryptography::GetNoise(char* dest, size_t size) {
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

#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}
#define SHA2_PACK32(str, x)                   \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}

void ::Cryptography::SHA::Private::sha256::init() {
    for(int i=0;i<8;i++) {
        m_h[i] = sqrts[i];
    }
    m_len = 0;
    m_tot_len = 0;
}
void ::Cryptography::SHA::Private::sha256::update(const unsigned char *message, unsigned int len) {
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}
void ::Cryptography::SHA::Private::sha256::transform(const unsigned char *message, unsigned int block_nb) {
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++) {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++) {
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                + ::Cryptography::SHA::Private::cbrts[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }
    }
}
void ::Cryptography::SHA::Private::sha256::final(unsigned char *digest) {
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                     < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0 ; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}
