namespace Cryptography {
    namespace AES {
        void AddRoundKey(uint8_t **state, uint8_t *key) {
            for(uint8_t i = 0; i < 4; i++) {
                for(uint8_t j = 0; j < 4; j++) {
                    state[i][j] = state[i][j] ^ key[i + 4 * j];
                }
            }
        }
        void SubBytes(uint8_t **state) {
            for(uint8_t i = 0; i < 4; i++) {
                for(uint8_t j = 0; j < 4; j++) {
                    state[i][j] = Sbox[state[i][j]];
                }
            }
        }
        void ShiftRow(uint8_t **state, uint8_t column, uint8_t shift) {
            for(uint8_t i = 0; i < 3; i+=shift) {
                state[column][i] = state[column][i+shift];
            }
        }
        void ShiftRows(uint8_t **state) {
            ShiftRow(state, 1, 1); ShiftRow(state, 2, 2); ShiftRow(state, 3, 3);
        }
        uint8_t GaloisFieldMul256(uint8_t a, uint8_t b) {
            uint8_t p = 0;
            for(uint8_t i = 0; i < 8; i++) {
                if((b & 1) != 0) {
                    p^=a;
                }
                bool high_bit_set = (a & 0x80) != 0;
                a <<= 1;
                if(high_bit_set) {
                    a ^= 0x11b;
                }
                b >>= 1;
            }
            return p;
        }
        void MixColumns(uint8_t **state) {
            for(uint8_t i = 0; i < 4; i++) {
#define mul GaloisFieldMul256
                state[i][0] = mul(0x02, state[i][0]) ^ mul(0x03, state[i][1]) ^ state[i][2] ^ state[i][3];
                state[i][1] = state[i][0] ^ mul(0x02, state[i][1]) ^ mul(0x03, state[i][2]) ^ state[i][3];
                state[i][2] = state[i][0] ^ state[i][1] ^ mul(0x02, state[i][2]) ^ mul(0x03, state[i][3]);
                state[i][3] = mul(0x03, state[i][0]) ^ state[i][1] ^ state[i][2] ^ mul(0x02, state[i][3]);
#undef mul
            }
        }

        void InvSubBytes(uint8_t **state) {
            for(uint8_t i = 0; i < 4; i++) {
                for(uint8_t j = 0; j < 4; j++) {
                    state[i][j] = InvSbox[state[i][j]];
                }
            }
        }
        void InvShiftRows(uint8_t **state) {
            ShiftRow(state, 1, 3); ShiftRow(state, 2, 2); ShiftRow(state, 3, 1);
        }
        void InvMixColumns(uint8_t **state) {
           for(uint8_t i = 0; i < 4; i++) {
                for(uint8_t j = 0; j < 4; j++) {
#define mul GaloisFieldMul256
                state[i][0] = mul(0x0e, state[i][0]) ^ mul(0x0b, state[i][1]) ^  mul(0x0d, state[i][2]) ^  mul(0x09, state[i][3]);
                state[i][1] = mul(0x09, state[i][0]) ^ mul(0x0e, state[i][1]) ^  mul(0x0b, state[i][2]) ^  mul(0x0d, state[i][3]);
                state[i][2] = mul(0x0d, state[i][0]) ^ mul(0x09, state[i][1]) ^  mul(0x0e, state[i][2]) ^  mul(0x0b, state[i][3]);
                state[i][3] = mul(0x0b, state[i][0]) ^ mul(0x0d, state[i][1]) ^  mul(0x09, state[i][2]) ^  mul(0x0e, state[i][3]);
#undef mul
                }
            }
        }
        void KeyExpansion(uint8_t* keySchedule, uint8_t* key) {
             memcpy(keySchedule, key, sizeof(uint8_t) * 4 * Nk);
             uint8_t *buf = (uint8_t*)malloc(4);

             for(uint16_t i = 4 * Nk; i < 16 * (Nr + 1); i += 4) {
                memcpy(buf, keySchedule + i - 4, 4);
                if(i / 4 % Nk == 0) {
                    ::std::reverse(buf, buf + 3);
                    for(int j=0;j<4;j++) {
                        buf[j] = Sbox[buf[j]];
                    }
                    for(uint8_t j = 0; j < 4; j++) {
                        buf[j] ^= Rcon[i / Nk][j];
                    }
                }
                else if (Nk > 6 && i / 4 % Nk == 4) {
                    for(int j=0;j<4;j++) {
                        buf[j] = Sbox[buf[j]];
                    }
                }
                for(int j = 0; j < 4; j++) {
                    keySchedule[i + j] =  keySchedule[i + j - 4 * Nk] ^ buf[j];
                }
             }
             free(buf);
        }
        void EncryptBlock(uint8_t **state, uint8_t *keySchedule) {
            AddRoundKey(state, keySchedule);
            for(uint8_t i = 0; i < Nr; i++) {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, keySchedule + i * 16);
            }
            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, keySchedule + Nr * 16);
        }
        void DecryptBlock(uint8_t **state, uint8_t *keySchedule) {
            AddRoundKey(state, keySchedule + Nr * 16);
            for(int i = Nr - 1; i >= 1; i--) {
                InvSubBytes(state);
                InvShiftRows(state);
                AddRoundKey(state, keySchedule + i * 16);
                InvMixColumns(state);
            }

            InvSubBytes(state);
            InvShiftRows(state);
            AddRoundKey(state, keySchedule);
        }
        size_t Encrypt(const char* in, size_t inLen, char** out, const char* key) {
            size_t outLen = ceil(double(inLen) / 32) * 32;
            (*out) = (char*)malloc(outLen);
            memset((*out),0,outLen);
            memcpy((*out),in,inLen);
            uint8_t *keySchedule = (uint8_t*)malloc(16 * (Nr + 1));
            KeyExpansion(keySchedule, (uint8_t*)key);
            uint8_t **state = (uint8_t**)malloc(sizeof(uint8_t*) * 4);
            for(size_t i = 0; i < outLen; i += 32) {
                for(uint8_t j = 0; j < 4; j++) {
                    state[j] = (uint8_t*)((*out) + i+j*4);
                }
                EncryptBlock(state, keySchedule);
            }
            free(state);
            free(keySchedule);
            return (inLen / 32) * 32;
        }
        size_t Decrypt(const char* in, size_t inLen, char** out, const char* key) {
            size_t outLen = ceil(double(inLen) / 32) * 32;
            (*out) = (char*)malloc(outLen);
            memset((*out),0,outLen);
            memcpy((*out),in,inLen);
            uint8_t *keySchedule = (uint8_t*)malloc(16 * (Nr + 1));
            KeyExpansion(keySchedule, (uint8_t*)key);
            uint8_t **state = (uint8_t**)malloc(sizeof(uint8_t*) * 4);
            for(size_t i = 0; i < outLen; i += 32) {
                for(uint8_t j = 0; j < 4; j++) {
                    state[j] = (uint8_t*)((*out) + i+j*4);
                }
                DecryptBlock(state, keySchedule);
            }
            free(state);
            free(keySchedule);
            return (inLen / 32) * 32;
        }
    }
}

#undef KEY_SIZE
#undef Nk
#undef Nr