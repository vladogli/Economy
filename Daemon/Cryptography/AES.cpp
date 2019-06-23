#include "AES.h"
#define Nb 4

#define Nk 8
#define Nr 14

constexpr uint8_t blockBytesLen = 4 * Nb * sizeof(uint8_t);
namespace Cryptography::AES {

uint8_t * EncryptECB(uint8_t in[], uint32_t inLen, uint8_t key[], uint32_t &outLen) {
  outLen = GetPaddingLength(inLen);
  uint8_t *alignIn  = PaddingNulls(in, inLen, outLen);
  uint8_t *out = (uint8_t*)malloc(outLen);
  for (uint32_t i = 0; i < outLen; i+= blockBytesLen) {
    EncryptBlock(alignIn + i, out + i, key);
  }
  delete[] alignIn;
  return out;
}

uint8_t * DecryptECB(uint8_t in[], uint32_t inLen, uint8_t key[], uint32_t &outLen) {
  outLen = GetPaddingLength(inLen);
  uint8_t *alignIn  = PaddingNulls(in, inLen, outLen);
  uint8_t *out = (uint8_t*)malloc(outLen);
  for (uint32_t i = 0; i < outLen; i+= blockBytesLen) {
    DecryptBlock(alignIn + i, out + i, key);
  }
  delete[] alignIn;
  return out;
}


uint8_t *EncryptCBC(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t * iv, uint32_t &outLen) {
  outLen = GetPaddingLength(inLen);
  uint8_t *alignIn  = PaddingNulls(in, inLen, outLen);
  uint8_t *out = (uint8_t*)malloc(outLen);
  uint8_t *block = new uint8_t[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (uint32_t i = 0; i < outLen; i+= blockBytesLen) {
    XorBlocks(block, alignIn + i, block, blockBytesLen);
    EncryptBlock(block, out + i, key);
  }
  delete[] block;
  delete[] alignIn;
  return out;
}

uint8_t *DecryptCBC(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t * iv, uint32_t &outLen) {
  outLen = GetPaddingLength(inLen);
  uint8_t *alignIn  = PaddingNulls(in, inLen, outLen);
  uint8_t *out = (uint8_t*)malloc(outLen);
  uint8_t *block = new uint8_t[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (uint32_t i = 0; i < outLen; i+= blockBytesLen) {
    DecryptBlock(alignIn + i, out + i, key);
    XorBlocks(block, out + i, out + i, blockBytesLen);
  }
  delete[] block;
  delete[] alignIn;
  return out;
}

uint8_t *EncryptCFB(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t * iv, uint32_t &outLen) {
  outLen = GetPaddingLength(inLen);
  uint8_t *alignIn  = PaddingNulls(in, inLen, outLen);
  uint8_t *out = (uint8_t*)malloc(outLen);
  uint8_t *block = new uint8_t[blockBytesLen];
  uint8_t *encryptedBlock = new uint8_t[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (uint32_t i = 0; i < outLen; i+= blockBytesLen) {
    EncryptBlock(block, encryptedBlock, key);
    XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, out + i, blockBytesLen);
  }
  delete[] block;
  delete[] encryptedBlock;
  delete[] alignIn;
  return out;
}

uint8_t *DecryptCFB(uint8_t in[], uint32_t inLen, uint8_t key[], uint8_t * iv, uint32_t &outLen) {
  outLen = GetPaddingLength(inLen);
  uint8_t *alignIn  = PaddingNulls(in, inLen, outLen);
  uint8_t *out = (uint8_t*)malloc(outLen);
  uint8_t *block = new uint8_t[blockBytesLen];
  uint8_t *encryptedBlock = new uint8_t[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (uint32_t i = 0; i < outLen; i+= blockBytesLen) {
    EncryptBlock(block, encryptedBlock, key);
    XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, alignIn + i, blockBytesLen);
  }
  delete[] block;
  delete[] encryptedBlock;
  delete[] alignIn;
  return out;
}

uint8_t * PaddingNulls(uint8_t in[], uint32_t inLen, uint32_t alignLen) {
  uint8_t * alignIn = new uint8_t[alignLen];
  memcpy(alignIn, in, inLen);
  return alignIn;
}

uint32_t GetPaddingLength(uint32_t len) {
  return (len / blockBytesLen) * blockBytesLen;
}

void EncryptBlock(uint8_t in[], uint8_t out[], uint8_t key[]) {
  uint8_t *w = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, w);
  uint8_t **state = new uint8_t *[4];
  state[0] = new uint8_t[4 * Nb];
  int i, j, round;
  for (i = 0; i < 4; i++) {
    state[i] = state[0] + Nb * i;
  }


  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, w);

  for (round = 1; round <= Nr - 1; round++) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, w + round * 4 * Nb);
  }

  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, w + Nr * 4 * Nb);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
  delete[] w;
}

void DecryptBlock(uint8_t in[], uint8_t out[], uint8_t key[]) {
  uint8_t *w = new uint8_t[4 * Nb * (Nr + 1)];
  KeyExpansion(key, w);
  uint8_t **state = new uint8_t *[4];
  state[0] = new uint8_t[4 * Nb];
  int i, j, round;
  for (i = 0; i < 4; i++) {
    state[i] = state[0] + Nb * i;
  }


  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, w + Nr * 4 * Nb);

  for (round = Nr - 1; round >= 1; round--) {
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, w + round * 4 * Nb);
    InvMixColumns(state);
  }

  InvSubBytes(state);
  InvShiftRows(state);
  AddRoundKey(state, w);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
  delete[] w;
}


void SubBytes(uint8_t **state) {
  int i, j;
  uint8_t t;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      t = state[i][j];
      state[i][j] = sbox[t / 16][t % 16];
    }
  }

}

void ShiftRow(uint8_t **state, int i, int n) { // shift row i on n positions
  uint8_t t;
  int k, j;
  for (k = 0; k < n; k++) {
    t = state[i][0];
    for (j = 0; j < Nb - 1; j++) {
      state[i][j] = state[i][j + 1];
    }
    state[i][Nb - 1] = t;
  }
}

void ShiftRows(uint8_t **state) {
  ShiftRow(state, 1, 1);
  ShiftRow(state, 2, 2);
  ShiftRow(state, 3, 3);
}

uint8_t xtime(uint8_t b) { // multiply on x
  uint8_t mask = 0x80, m = 0x1b;
  uint8_t high_bit = b & mask;
  b = b << 1;
  if (high_bit) {    // mod m(x)
    b = b ^ m;
  }
  return b;
}

uint8_t mul_bytes(uint8_t a, uint8_t b) {
  uint8_t c = 0, mask = 1, bit, d;
  int i, j;
  for (i = 0; i < 8; i++) {
    bit = b & mask;
    if (bit) {
      d = a;
      for (j = 0; j < i; j++) {    // multiply on x^i
        d = xtime(d);
      }
      c = c ^ d;    // xor to result
    }
    b = b >> 1;
  }
  return c;
}

void MixColumns(uint8_t **state) {
  uint8_t s[4], s1[4];
  int i, j;

  for (j = 0; j < Nb; j++) {
    for (i = 0; i < 4; i++) {
      s[i] = state[i][j];
    }

    s1[0] = mul_bytes(0x02, s[0]) ^ mul_bytes(0x03, s[1]) ^ s[2] ^ s[3];
    s1[1] = s[0] ^ mul_bytes(0x02, s[1]) ^ mul_bytes(0x03, s[2]) ^ s[3];
    s1[2] = s[0] ^ s[1] ^ mul_bytes(0x02, s[2]) ^ mul_bytes(0x03, s[3]);
    s1[3] = mul_bytes(0x03, s[0]) ^ s[1] ^ s[2] ^ mul_bytes(0x02, s[3]);
    for (i = 0; i < 4; i++) {
      state[i][j] = s1[i];
    }

  }

}

void AddRoundKey(uint8_t **state, uint8_t *key) {
  int i, j;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[i][j] = state[i][j] ^ key[i + 4 * j];
    }
  }
}

void SubWord(uint8_t *a) {
  int i;
  for (i = 0; i < 4; i++) {
    a[i] = sbox[a[i] / 16][a[i] % 16];
  }
}

void RotWord(uint8_t *a) {
  uint8_t c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

void XorWords(uint8_t *a, uint8_t *b, uint8_t *c) {
  int i;
  for (i = 0; i < 4; i++) {
    c[i] = a[i] ^ b[i];
  }
}

void Rcon(uint8_t * a, int n) {
  int i;
  uint8_t c = 1;
  for (i = 0; i < n - 1; i++) {
    c = xtime(c);
  }

  a[0] = c;
  a[1] = a[2] = a[3] = 0;
}

void KeyExpansion(uint8_t key[], uint8_t w[]) {
  uint8_t *temp = new uint8_t[4];
  uint8_t *rcon = new uint8_t[4];

  int i = 0;
  while (i < 4 * Nk) {
    w[i] = key[i];
    i++;
  }

  i = 4 * Nk;
  while (i < 4 * Nb * (Nr + 1)) {
    temp[0] = w[i - 4 + 0];
    temp[1] = w[i - 4 + 1];
    temp[2] = w[i - 4 + 2];
    temp[3] = w[i - 4 + 3];

    if (i / 4 % Nk == 0) {
        RotWord(temp);
        SubWord(temp);
        Rcon(rcon, i / (Nk * 4));
      XorWords(temp, rcon, temp);
    }
    else if (Nk > 6 && i / 4 % Nk == 4) {
      SubWord(temp);
    }

    w[i + 0] = w[i - 4 * Nk] ^ temp[0];
    w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
    w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
    w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
    i += 4;
  }

  delete []rcon;
  delete []temp;

}


void InvSubBytes(uint8_t **state) {
  int i, j;
  uint8_t t;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      t = state[i][j];
      state[i][j] = inv_sbox[t / 16][t % 16];
    }
  }
}

void InvMixColumns(uint8_t **state) {
  uint8_t s[4], s1[4];
  int i, j;

  for (j = 0; j < Nb; j++) {
    for (i = 0; i < 4; i++) {
      s[i] = state[i][j];
    }
    s1[0] = mul_bytes(0x0e, s[0]) ^ mul_bytes(0x0b, s[1]) ^ mul_bytes(0x0d, s[2]) ^ mul_bytes(0x09, s[3]);
    s1[1] = mul_bytes(0x09, s[0]) ^ mul_bytes(0x0e, s[1]) ^ mul_bytes(0x0b, s[2]) ^ mul_bytes(0x0d, s[3]);
    s1[2] = mul_bytes(0x0d, s[0]) ^ mul_bytes(0x09, s[1]) ^ mul_bytes(0x0e, s[2]) ^ mul_bytes(0x0b, s[3]);
    s1[3] = mul_bytes(0x0b, s[0]) ^ mul_bytes(0x0d, s[1]) ^ mul_bytes(0x09, s[2]) ^ mul_bytes(0x0e, s[3]);

    for (i = 0; i < 4; i++)
    {
      state[i][j] = s1[i];
    }
  }
}

void InvShiftRows(uint8_t **state) {
  ShiftRow(state, 1, Nb - 1);
  ShiftRow(state, 2, Nb - 2);
  ShiftRow(state, 3, Nb - 3);
}

void XorBlocks(uint8_t *a, uint8_t * b, uint8_t *c, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    c[i] = a[i] ^ b[i];
  }
}
}