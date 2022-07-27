/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <stdlib.h>
#include <string.h> // CBC mode, for memset
#include "mico_aes.h"
 
/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
 
#if (AES___ == 256) || (AES___ == 192)
 #if(AES___ == 256)
 #define AES256
 #endif
#define  KEYLEN (AES___/8)
#else
#define  AES128
#define  KEYLEN       (16) // Key length in bytes
#endif
 
#define  BLOCKLEN (128 /8) // Block length in AES is always 128-bits.
#define  Nb  (BLOCKLEN /4) // The number of columns comprising a state in AES
#define  Nk    (KEYLEN /4) // The number of 32 bit words in a key.
#define  ROUNDS    (Nk +6) // The number of rounds in AES Cipher.
 
 
 
 
/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[Nb][4];
static state_t* state;
 
// The array that stores the round keys.
// AES-128 has 10 rounds, + one AddRoundKey before first round: 16x(10+1)=176.
static uint8_t RoundKey[BLOCKLEN * (ROUNDS + 1)];
 
#if defined(CBC) && CBC
    // Initial Vector used only for CBC mode
    static uint8_t* Iv;
#endif
 
 
// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] =
{
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
 
#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static const uint8_t rsbox[256] =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
#endif
 
 
/*****************************************************************************/
/* Auxiliary functions for AES-128 and AES-GCM algorithm:                    */
/*****************************************************************************/
 
#define getSBoxValue(num)  (sbox[(num)])
#define getSBoxInvert(num) (rsbox[(num)])
 
 
// auxiliary function for Multiplication in GF(2^8)
static uint8_t xtime (uint8_t x)
{
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}
 
// performs XOR operation on two 128-bit blocks
static void xorBlock (uint8_t *dest, const uint8_t *src)
{
    uint32_t *d, *s;
    d = (uint32_t *) dest;
    s = (uint32_t *) src;
    *d++ ^= *s++;
    *d++ ^= *s++;
    *d++ ^= *s++;
    *d++ ^= *s++;
/*
    uint8_t i;
    for (i = 0; i < BLOCKLEN; i++)
    {
        *dest++ ^= *src++;
    }
*/
}
 
// increments the rightmost 32 bits (4 bytes) of block, %(2^32)
static void incr32 (uint8_t *pBlock)
{
    uint8_t i;
    // go to end of array
    pBlock += BLOCKLEN - 1;
 
    // loop through last 4 elements
    for (i = 0; i < 4; ++i)
    {
        // return if no overflow, otherwise move to next byte
        if (++*pBlock) return;
        else --pBlock;
    }
}
 
// Multiply numbers in the field GF(2^8)
static uint8_t GF_Mul8 (uint8_t x, uint8_t y)
{
    uint8_t m;
 
    m = 0;
    for (;;)
    {
        if (y  &  1) m ^= x;
        if (y >>= 1) x = xtime (x);
        else return m;
    }
}
/*
// defining GF-Multiply as a function is way more efficient
#define GF_Mul8(x, y)                                \
    ( ((y      & 1) * x) ^                           \
      ((y >> 1 & 1) * xtime(x)) ^                    \
      ((y >> 2 & 1) * xtime(xtime(x))) ^             \
      ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^      \
      ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))) )
*/
 
// bit-shifts right a 128-bit block (16 byte array) once
// this is auxiliary function for multiply in GF(2^128)
// block points to the LAST ELEMENT
static uint8_t shiftBlockRight (uint8_t *block)
{
    uint8_t i, p;    // p is the parity bit of the block
 
    i = BLOCKLEN;
    p = *block & 1;
 
    // loop through bytes, from last to first
    for (;;)
    {
        // bit shift byte
        *block-- >>= 1;
        // if we reached the first byte:
        if (!--i)  return p;
        // if LSB is set, set MSB of next byte in array
        if (*block & 1)  *(block + 1) |= 0x80;
    }
}
 
// Performs multiplications in 128 bit Galois bit field
static void GF_Mul128 (const uint8_t *x, const uint8_t *y, uint8_t *result)
{
    // working memory
    uint8_t i, j, temp[BLOCKLEN];
 
    // init result to 0s and copy y to temp
    memcpy(temp, y, BLOCKLEN);
    memset(result, 0, BLOCKLEN);
 
    // multiplication algorithm
    for (i = 0; i < BLOCKLEN; i++)
    {
        for (j = 0x80; j != 0; j >>= 1)
        {
            if (x[i] & j)
            {
                /* Z_(i + 1) = Z_i XOR V_i */
                xorBlock(result, temp);
            }
            /* V_(i + 1) = (V_i >> 1) XOR R */
            if (shiftBlockRight (temp + BLOCKLEN - 1))
            {
                // if temp is odd, do something?
                /* R = 11100001 || 0^120 */
                temp[0] ^= 0xe1;
            }
        }
    }
}
 
/*****************************************************************************/
/* Private functions for the AES algorithm:                                  */
/*****************************************************************************/
 
// This function produces Nb(Nr+1) round keys.
// The round keys are used in each round to encrypt/decrypt the states.
static void KeyExpansion (const uint8_t* key)
{
    uint8_t i, r, *n, *b, temp[4]; // Used for the column/row operations
    r = 1;                         // RCON
    b = RoundKey;                  // current block
    n = RoundKey + KEYLEN;         // next block
 
    // The first round key is the key itself.
    memcpy (RoundKey, key, KEYLEN);
 
    // All other round keys are found from the previous round keys.
    for (i = 0; i < Nb * ROUNDS; ++i)
    {
        if (i % Nk)
        {
            memcpy (temp, n - 4, 4);
        }
        else
        {
            temp[0] = getSBoxValue (*(n - 3)) ^ r;
            temp[1] = getSBoxValue (*(n - 2)) ;
            temp[2] = getSBoxValue (*(n - 1)) ;
            temp[3] = getSBoxValue (*(n - 4)) ;
            r = xtime (r);
        }
#ifdef AES256
        if (i % Nk == 4)
        {
            temp[0] = getSBoxValue (temp[0]);
            temp[1] = getSBoxValue (temp[1]);
            temp[2] = getSBoxValue (temp[2]);
            temp[3] = getSBoxValue (temp[3]);
        }
#endif
        *n++ = *b++ ^ temp[0];
        *n++ = *b++ ^ temp[1];
        *n++ = *b++ ^ temp[2];
        *n++ = *b++ ^ temp[3];
    }
}
 
// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey (uint8_t round)
{
    xorBlock ((*state)[0], RoundKey + BLOCKLEN * round);
}
 
// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes (uint8_t* s)
{
    uint8_t i;
    for (i = 0; i < BLOCKLEN; ++i)
    {
        *s = getSBoxValue (*s);
        ++s;
    }
}
 
// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows (void)
{
    uint8_t temp;
 
    // Rotate first row 1 columns to left
    temp           = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;
 
    // Rotate second row 2 columns to left
    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
 
    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;
 
    // Rotate third row 3 columns to left
    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}
 
// MixColumns function mixes the columns of the state matrix
static void MixColumns (uint8_t* s)
{
    uint8_t a, b, c, d, i;
    for (i = 0; i < Nb; ++i)
    {
        a  = s[0] ^ s[1];
        b  = s[1] ^ s[2];
        c  = s[2] ^ s[3];
        d     = a ^ c;
        *s++ ^= d ^ xtime (a);
        *s++ ^= d ^ xtime (b);
        b    ^= d;
        *s++ ^= d ^ xtime (c);
        *s++ ^= d ^ xtime (b);
    }
}
 
// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns (uint8_t* s)
{
    uint8_t a, b, c, d, i;
 
    for (i = 0; i < Nb; ++i)
    {
        a = s[0];
        b = s[1];
        c = s[2];
        d = s[3];
 
        *s++ = GF_Mul8 (a, 0x0e) ^ GF_Mul8 (b, 0x0b) ^ GF_Mul8 (c, 0x0d) ^ GF_Mul8 (d, 0x09);
        *s++ = GF_Mul8 (a, 0x09) ^ GF_Mul8 (b, 0x0e) ^ GF_Mul8 (c, 0x0b) ^ GF_Mul8 (d, 0x0d);
        *s++ = GF_Mul8 (a, 0x0d) ^ GF_Mul8 (b, 0x09) ^ GF_Mul8 (c, 0x0e) ^ GF_Mul8 (d, 0x0b);
        *s++ = GF_Mul8 (a, 0x0b) ^ GF_Mul8 (b, 0x0d) ^ GF_Mul8 (c, 0x09) ^ GF_Mul8 (d, 0x0e);
    }
}
 
// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes (uint8_t* s)
{
    uint8_t i;
    for (i = 0; i < BLOCKLEN; ++i)
    {
        *s = getSBoxInvert (*s);
        ++s;
    }
}
 
// The InvShiftRows function shifts the rows in the state to the right.
static void InvShiftRows (void)
{
    uint8_t temp;
 
    // Rotate first row 1 columns to right
    temp           = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;
 
    // Rotate second row 2 columns to right
    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
 
    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;
 
    // Rotate third row 3 columns to right
    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}
 
/*****************************************************************************/
/* Main functions of the AES-128:                                            */
/*****************************************************************************/
 
// initialize and set the 128-bit encryption key
static void AES128_setkey (const uint8_t* key)
{
    // The KeyExpansion routine must be called before encryption/decryption.
    KeyExpansion (key);
}
 
// Encrypt input (128-bit plain-text) into a 128-bit cipher text as output
static void AES_EncryptBlock (const uint8_t* input, uint8_t* output)
{
    // Copy input to output, and work in-memory on output
    memcpy (output, input, BLOCKLEN);
    state = (state_t*) output;
 
    uint8_t round;
 
    // There will be #ROUNDS rounds.
    // The first #ROUNDS-1 rounds are identical.
    // The last one does not involve mixing columns
    round = 0;
    for (;;)
    {
        AddRoundKey (round++);
        SubBytes (output);
        ShiftRows();
        if (round < ROUNDS) MixColumns (output);
        else break;
    }
 
    // Add the last round key to the state after finishing the rounds.
    AddRoundKey (ROUNDS);
}
 
// Decrypt input (128-bit cipher-text) into a 128-bit plain text as output
static void AES_DecryptBlock (const uint8_t* input, uint8_t* output)
{
    // Copy input to output, and work in-memory on output
    memcpy (output, input, BLOCKLEN);
    state = (state_t*) output;
 
    // Add the last round key to the state before starting the rounds.
    AddRoundKey (ROUNDS);
 
    uint8_t round;
 
    // There will be #ROUNDS rounds.
    // The first #ROUNDS-1 rounds are identical.
    // The last one does not involve mixing columns
    round = ROUNDS;
    for (;;)
    {
        InvShiftRows();
        InvSubBytes (output);
        AddRoundKey (--round);
        if (round) InvMixColumns (output);
        else break;
    }
}
 
/*****************************************************************************/
/* Main functions of AES-GCM:                                                */
/*****************************************************************************/
 
/**
 * @note    aes_gcm_initialize and generate authentication subkey H
 * @brief   performs AES key expansion and making authentication key
 * @param   pKey            pointer to the provided 128 bit AES key
 * @param   pAuthKey        pointer to 16 byte array put to subkey H in
 */
static void generateKeys( const uint8_t *pKey, uint8_t *pAuthKey )
{
    AES128_setkey( pKey );
    // encrypt 128 bit block of 0s to generate authentication sub key
    memset(pAuthKey, 0, BLOCKLEN);
    AES_EncryptBlock(pAuthKey, pAuthKey);
}
 
/**
 * @note    aes_gctr
 * @brief   performs gcntr operation for encryption
 * @param   pInput          pointer to input data
 * @param   inputLength     length of input array
 * @param   pICB            initial counter block J0
 * @param   pOutput         pointer to output data. same length as input.
 */
static void GCTR( const uint8_t *pInput,
                  uint16_t inputLength,
                  const uint8_t *pCtrBlock,
                  uint8_t *pOutput )
{
    if (inputLength == 0) return;
 
    uint8_t n, *p, *xpos, *ypos, ctrBlock[BLOCKLEN];
 
    xpos = (uint8_t*) pInput;
    ypos = pOutput;
    p = ctrBlock;
 
    // calculate number of full blocks to cipher
    n = (uint8_t) (inputLength / BLOCKLEN);
 
    // copy ICB to ctrBlock
    memcpy(ctrBlock, pCtrBlock, BLOCKLEN);
 
    // for full blocks
    while (n--)
    {
        // cipher counterblock and combine with input
        AES_EncryptBlock(ctrBlock, ypos);
        xorBlock(ypos, xpos);
 
        // increment pointers to next block
        xpos += BLOCKLEN;
        ypos += BLOCKLEN;
 
        // increment counter
        incr32(ctrBlock);
    }
 
    // check if there is a partial block at end
    n = (uint8_t) (inputLength % BLOCKLEN);
    if( n )
    {
        // encrypt into tmp and combine with last block of input
        AES_EncryptBlock(ctrBlock, ctrBlock);
        while (n--)  *ypos++ = *xpos++ ^ *p++;
    }
}

/**
 * @note    ghash
 * @brief   performs authentication hashing
 * @todo    is final memcpy always persistent?
 * @param   pInput          pointer to input data
 * @param   inputLength     length of input array
 * @param   pAuthKey        pointer to 128 bit authentication subkey H
 * @param   pOutput         pointer to 16 byte output array
 */
static void GHASH( const uint8_t *pInput,
                   uint16_t inputLength,
                   const uint8_t *pAuthKey,
                   uint8_t *pOutput )
{
    if (inputLength == 0) return;
 
    uint8_t m, tmp[BLOCKLEN]; // if we use full blocks, no need for tmp
    const uint8_t *xpos = pInput;
 
    // calculate number of full blocks to hash
    m = (uint8_t) (inputLength / BLOCKLEN);
 
    // hash full blocks
    while (m--)
    {
        // Y_i = (Y^(i-1) XOR X_i) dot H
        xorBlock(pOutput, xpos);
        xpos += BLOCKLEN; // move to next block
 
        GF_Mul128(pOutput, pAuthKey, tmp);
 
        // copy tmp to output
        memcpy(pOutput, tmp, BLOCKLEN);
    }
 
    m = (uint8_t) (inputLength % BLOCKLEN);  // last block
    // check if final partial block. Can be omitted if we use full blocks.
    if( m )
    {
        // zero pad
        memcpy(tmp, xpos, m);
        memset(tmp + m, 0, BLOCKLEN - m);
 
        // Y_i = (Y^(i-1) XOR X_i) dot H
        xorBlock(pOutput, tmp);
        GF_Mul128(pOutput, pAuthKey, tmp);
        memcpy(pOutput, tmp, BLOCKLEN);
    }
}
 
/**
 * @note    aes_gcm_prepare_j0
 * @brief   generates initial counter block from IV
 * @param   pIV             pointer to 12 byte initial vector nonce
 * @param   pOutput         pointer to 16 byte output array
 */
static void generateICB(const uint8_t *pIV, uint8_t *pOutput)
{
    // Prepare block J0 = IV || 0^31 || 1 [len(IV) = 96]
    memcpy(pOutput, pIV, GCM_IV_SIZE);
    memset(pOutput + GCM_IV_SIZE, 0, BLOCKLEN - GCM_IV_SIZE);
    pOutput[BLOCKLEN - 1] = 0x01;
}
 
/**
 * @note    aes_gcm_ctr
 * @brief   encrypt PDATA to get CDATA
 * @param   pICB        pointer to initial counter block
 * @param   pPDATA      pointer to plain text
 * @param   PDATALength length of plain text
 * @param   pCDATA      pointer to array for cipher text
 */
static void generateCDATA( const uint8_t *pICB,
                           const uint8_t *pPDATA,
                           uint16_t PDATALength,
                           uint8_t *pCDATA )
{
    // generate counterblock J
    uint8_t ctrBlock[BLOCKLEN];
    memcpy(ctrBlock, pICB, BLOCKLEN);
    incr32(ctrBlock);
 
    // encrypt
    GCTR(pPDATA, PDATALength, ctrBlock, pCDATA);
}
 
/**
 * @note    aes_gcm_ghash
 * @brief   makes message S from ADATA and CDATA
 * @param   pADATA          pointer to array containing authentication data
 * @param   ADATALength     length of ADATA array
 * @param   pCDATA          pointer to array containing encrypted data
 * @param   CDATALength     length of CDATA array
 * @param   pAuthKey        pointer to 128 bit authentication subkey H
 * @param   pTag            pointer to array to store tag
 */
static void generateTag( const uint8_t *pAuthKey,
                         const uint8_t *pADATA,
                         uint16_t ADATALength,
                         const uint8_t *pCDATA,
                         uint16_t CDATALength,
                         uint8_t * pTag,
                         const uint8_t *pICB)
{
    uint8_t lengthBuffer[BLOCKLEN];
    uint8_t S[BLOCKLEN];
    memset(lengthBuffer, 0, BLOCKLEN);
    memset(S, 0, BLOCKLEN);
    /*
     * u = 128 * ceil[len(C)/128] - len(C)
     * v = 128 * ceil[len(A)/128] - len(A)
     * S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
     * (i.e., zero padded to block size A || C and lengths of each in bits)
     */
 
    // function to put [len(A)]64 || [len(C)]64 in temp. could be saved as using fixed method length
    // the rest of bytes are not needed as we assume Length < 4Kb
    lengthBuffer[6]  = (ADATALength >> 5) & 0xff;
    lengthBuffer[7]  = (ADATALength << 3) & 0xff;
    lengthBuffer[14] = (CDATALength >> 5) & 0xff;
    lengthBuffer[15] = (CDATALength << 3) & 0xff;
 
    GHASH(pADATA, ADATALength, pAuthKey, S);
    GHASH(pCDATA, CDATALength, pAuthKey, S);
    GHASH(lengthBuffer, BLOCKLEN, pAuthKey, S);
 
    GCTR(S, BLOCKLEN, pICB, pTag);
}

/**
 * @note    aes_gcm_ae
 * @brief   performs aesgcm encryption
 * @todo    should this be a void?
 * @param   key             pointer to 16 byte (128 bit) key
 * @param   IV              pointer to IV
 * @param   PDATA           pointer to plaintext array
 * @param   PDATA_length    length of plaintext array
 * @param   ADATA           pointer to additional data array
 * @param   ADATA_length    length of additional data
 * @param   messageTag      pointer to 16 byte buffer to output tag to
 * @param   CDATA           buffer to output ciphertext to
 */
static uint8_t aes128_gcm_encrypt( const uint8_t* key,
                                   const uint8_t* IV,
                                   const uint8_t* PDATA,
                                   const uint16_t PDATALength,
                                   const uint8_t* ADATA,
                                   const uint16_t ADATALength,
                                   uint8_t* messageTag,
                                   uint8_t* CDATA )
{
    uint8_t authKey[BLOCKLEN];
    uint8_t ICB[BLOCKLEN];
 
    generateKeys(key, authKey);     // aes_key_expand & aes_gcm_init_hash_subkey
    generateICB(IV, ICB);           // aes_gcm_prepare_j0
 
    generateCDATA(ICB, PDATA, PDATALength, CDATA);
 
    generateTag(authKey, ADATA, ADATALength, CDATA, PDATALength, messageTag, ICB);
 
    return 0;
}
 
/**
 * @note    aes_gcm_ad
 * @brief   performs aesgcm decryption and authentication
 * @todo    How to do data hiding on authentication fail?
 *              - when put into classes?
 *              - wipe array?
 *              - make PDATA private and then only pass pointer if true?
 *          Should this be a bool?
 * @param   key:            pointer to 16 byte (128 bit) key
 * @param   IV:             pointer to IV
 * @param   CDATA:          pointer to ciphertext array
 * @param   CDATALength:    length of ciphertext array
 * @param   ADATA:          pointer to additional data array
 * @param   ADATALength:    length of additional data
 * @param   messageTag:     pointer to the authentication tag (if any)
 * @param   tagLength:      length of authentication tag buffer
 * @param   PDATA:          buffer to the output plaintext
 * @retval  returns true if authenticated, else returns false
 */
static uint8_t aes128_gcm_decrypt( const uint8_t* key,
                                   const uint8_t* IV,
                                   const uint8_t* CDATA,
                                   const uint16_t CDATALength,
                                   const uint8_t* ADATA,
                                   const uint16_t ADATALength,
                                   const uint8_t* messageTag,
                                   const uint8_t  tagLength,
                                   uint8_t* PDATA )
{
    uint8_t authKey[BLOCKLEN];
    uint8_t ICB[BLOCKLEN];
    uint8_t calculatedTag[GCM_TAG_SIZE];
 
    generateKeys(key, authKey);     // aes_key_expand & aes_gcm_init_hash_subkey
    generateICB(IV, ICB);           // aes_gcm_prepare_j0
 
    generateTag(authKey, ADATA, ADATALength, CDATA, CDATALength, calculatedTag, ICB);
 
    // function to compare tags and return 0 if they match
    if (memcmp( calculatedTag, messageTag, tagLength ) != 0)
    {
        return AUTHENTICATION_FAILURE;
    }
 
    generateCDATA(ICB, CDATA, CDATALength, PDATA);
 
    return 0;
}
