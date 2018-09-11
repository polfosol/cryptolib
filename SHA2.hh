#ifndef SHA2_h___
#define SHA2_h___

#include <cstdio>
#include <string>
#include <cstring>
#include <stdint.h>
#include <sys/stat.h>

#ifdef _MSC_VER
#define stat64    _stat64
#endif

namespace sha2
{
    namespace templates
    {
        typedef enum
        {
            SHA_256,
            SHA_224,
            SHA_512,
            SHA_384,
            SHA_512_256,
            SHA_512_224,
            SHA_512_xxx,    /// to define new hash functions, replace xxx by your desired number
        } hash_method;

        /// initializer vectors (first 64 bits of the fractional parts of the square roots of primes)
        static const uint64_t sha512_init_vectors[][8] =
        {
            /// sha512, primes: 2-19 (their 32 MSBs are also used in sha256)
            { 0x6A09E667F3BCC908LL, 0xBB67AE8584CAA73BLL, 0x3C6EF372FE94F82BLL, 0xA54FF53A5F1D36F1LL,
            0x510E527FADE682D1LL, 0x9B05688C2B3E6C1FLL, 0x1F83D9ABFB41BD6BLL, 0x5BE0CD19137E2179LL },
            /// sha384, primes: 23-53 (their 32 LSBs are also used in sha224)
            { 0xCBBB9D5DC1059ED8LL, 0x629A292A367CD507LL, 0x9159015A3070DD17LL, 0x152FECD8F70E5939LL,
            0x67332667FFC00B31LL, 0x8EB44A8768581511LL, 0xDB0C2E0D64F98FA7LL, 0x47B5481DBEFA4FA4LL },
            /// SHA-512/256 (calculated using the "SHA-512/t IV Generation Function")
            { 0x22312194FC2BF72CLL, 0x9F555FA3C84C64C2LL, 0x2393B86B6F53B151LL, 0x963877195940EABDLL,
            0x96283EE2A88EFFE3LL, 0xBE5E1E2553863992LL, 0x2B0199FC2C85B8AALL, 0x0EB72DDC81C52CA2LL },
            /// SHA-512/224 (-->section 5.3.6 of http://goo.gl/VtJ5Uv)
            { 0x8C3D37C819544DA2LL, 0x73E1996689DCD4D6LL, 0x1DFAB7AE32FF9C82LL, 0x679DD514582F9FCFLL,
            0x0F6D2B697BD44DA8LL, 0x77E36F7304C48942LL, 0x3F9D85A86A1D36C8LL, 0x1112E6AD91D692A1LL },
            /// you can insert the I.V. of the new hash functions here...
        };

        /// hash round-table (first 64 bits of the fractional parts of the cube roots of primes: 2-409)
        static const uint64_t sha512_round_table[80] =
        {
            0x428A2F98D728AE22LL, 0x7137449123EF65CDLL, 0xB5C0FBCFEC4D3B2FLL, 0xE9B5DBA58189DBBCLL,
            0x3956C25BF348B538LL, 0x59F111F1B605D019LL, 0x923F82A4AF194F9BLL, 0xAB1C5ED5DA6D8118LL,
            0xD807AA98A3030242LL, 0x12835B0145706FBELL, 0x243185BE4EE4B28CLL, 0x550C7DC3D5FFB4E2LL,
            0x72BE5D74F27B896FLL, 0x80DEB1FE3B1696B1LL, 0x9BDC06A725C71235LL, 0xC19BF174CF692694LL,
            0xE49B69C19EF14AD2LL, 0xEFBE4786384F25E3LL, 0x0FC19DC68B8CD5B5LL, 0x240CA1CC77AC9C65LL,
            0x2DE92C6F592B0275LL, 0x4A7484AA6EA6E483LL, 0x5CB0A9DCBD41FBD4LL, 0x76F988DA831153B5LL,
            0x983E5152EE66DFABLL, 0xA831C66D2DB43210LL, 0xB00327C898FB213FLL, 0xBF597FC7BEEF0EE4LL,
            0xC6E00BF33DA88FC2LL, 0xD5A79147930AA725LL, 0x06CA6351E003826FLL, 0x142929670A0E6E70LL,
            0x27B70A8546D22FFCLL, 0x2E1B21385C26C926LL, 0x4D2C6DFC5AC42AEDLL, 0x53380D139D95B3DFLL,
            0x650A73548BAF63DELL, 0x766A0ABB3C77B2A8LL, 0x81C2C92E47EDAEE6LL, 0x92722C851482353BLL,
            0xA2BFE8A14CF10364LL, 0xA81A664BBC423001LL, 0xC24B8B70D0F89791LL, 0xC76C51A30654BE30LL,
            0xD192E819D6EF5218LL, 0xD69906245565A910LL, 0xF40E35855771202ALL, 0x106AA07032BBD1B8LL,
            0x19A4C116B8D2D0C8LL, 0x1E376C085141AB53LL, 0x2748774CDF8EEB99LL, 0x34B0BCB5E19B48A8LL,
            0x391C0CB3C5C95A63LL, 0x4ED8AA4AE3418ACBLL, 0x5B9CCA4F7763E373LL, 0x682E6FF3D6B2B8A3LL,
            0x748F82EE5DEFB2FCLL, 0x78A5636F43172F60LL, 0x84C87814A1F0AB72LL, 0x8CC702081A6439ECLL,
            0x90BEFFFA23631E28LL, 0xA4506CEBDE82BDE9LL, 0xBEF9A3F7B2C67915LL, 0xC67178F2E372532BLL,
            0xCA273ECEEA26619CLL, 0xD186B8C721C0C207LL, 0xEADA7DD6CDE0EB1ELL, 0xF57D4F7FEE6ED178LL,
            0x06F067AA72176FBALL, 0x0A637DC5A2C898A6LL, 0x113F9804BEF90DAELL, 0x1B710B35131C471BLL,
            0x28DB77F523047D84LL, 0x32CAAB7B40C72493LL, 0x3C9EBE0A15C9BEBCLL, 0x431D67C49C100D4CLL,
            0x4CC5D4BECB3E42B6LL, 0x597F299CFC657E2ALL, 0x5FCB6FAB3AD6FAECLL, 0x6C44198C4A475817LL
        };

        /// shift|rotate amounts in digest and round process
        static const char shift_rotate_amounts[24] =
        {
            6, 11, 25, 2, 13, 22, 7, 18, 3, 17, 19, 10, 14, 18, 41, 28, 34, 39, 1, 8, 7, 19, 61, 6
        };

        static const char* B64Ch = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        ///======================< structure to save hash data >=========================
        struct hashdata
        {
            std::basic_string <uint8_t> bytes;  /// byte array of hash number

            hashdata(const uint8_t* sequence, const size_t& len)
            {
                bytes = std::basic_string <uint8_t> (sequence, len);
            }

            const std::string toHex(bool lowercase = true)  /// hex representation of the hash
            {
                const size_t letter = lowercase ? 0x50 : 0x70;
                std::string hexstr(bytes.size() * 2, '0');
                for (size_t i = 0, c = bytes[0]; i < hexstr.size(); c = bytes[i / 2])
                {
                    hexstr[i++] ^= c > 0x9F ? (c / 16 - 9) | letter : c >> 4;
                    hexstr[i++] ^= (c & 0xF) > 9 ? (c % 16 - 9) | letter : c & 0xF;
                }
                return hexstr;
            }

            const std::string toBase64()  /// base64 representation of the hash
            {
                size_t pad = bytes.size() % 3;
                const size_t len = bytes.size() - pad;
                std::string str64(4 * (int(pad > 0) + len / 3), '=');

                for (size_t i = 0, j = 0; i < len; i += 3)
                {
                    int n = int(bytes[i]) << 16 | int(bytes[i + 1]) << 8 | bytes[i + 2];
                    str64[j++] = B64Ch[n >> 18 & 0x3F];
                    str64[j++] = B64Ch[n >> 12 & 0x3F];
                    str64[j++] = B64Ch[n >> 6 & 0x3F];
                    str64[j++] = B64Ch[n & 0x3F];
                }
                if (pad--)  /// padding
                {
                    int n = pad ? int(bytes[len]) << 8 | bytes[len + 1] : bytes[len];
                    str64[str64.size() - 4] = B64Ch[pad ? n >> 10 & 0x3F : n >> 2];
                    str64[str64.size() - 3] = B64Ch[pad ? n >> 4 & 0x03F : n << 4 & 0x3F];
                    str64[str64.size() - 2] = pad ? B64Ch[n << 2 & 0x3F] : '=';
                }
                return str64;
            }
        };

        ///=================< General hash algorithm class template >====================
        template <typename T = uint32_t, hash_method H = SHA_256, int Hash_Size = 256>
        class general_sha2
        {
        private:
            T num[8];                            /// hash number
            uint8_t bytes[8 * sizeof(T)];        /// byte sequence of hash number
            const T *round_table, *init_vector;  /// round table & initialization vector
            const uint8_t *sr;                   /// shift|rotate values

        public:
            ///------ constructor and initializer
            inline general_sha2()
            {
                sr = (uint8_t const*)& shift_rotate_amounts[sizeof(T) == 8 ? 12 : 0];
                if (sizeof(T) == 8)  /// is 64-bit based hash (SHA512)
                {
                    round_table = (T const*)(void*)& sha512_round_table[0];
                    init_vector = (T const*)(void*)& sha512_init_vectors[H - SHA_512][0];
                    return;
                }
                static uint32_t table_iv_32[80], i = 0;  /// 32-bit based hashes
                if (table_iv_32[0] == 0)  /// loops are skipped if static array is already filled.
                {
                    for (; i < 64; ++i) table_iv_32[i] = sha512_round_table[i] >> 32;   // MSBs
                    for (; i < 72; ++i) table_iv_32[i] = sha512_init_vectors[0][i & 7] >> 32;
                    for (; i < 80; ++i) table_iv_32[i] = sha512_init_vectors[1][i & 7]; // for SHA224
                }
                round_table = (T const*)(void*)& table_iv_32[0];
                init_vector = (T const*)(void*)& table_iv_32[64 + 8 * (H - SHA_256)];
            }

            ///------ destructor
            virtual ~general_sha2(){}

        private:
            enum
            {
                BitCount = 8 * sizeof(T),
                BlockSize = 16 * sizeof(T),
                Rounds = 64 + 16 * (sizeof(T) / 8)
            };

            ///------ right rotation
            T ror(T val, unsigned r)
            {
                return (val >> r) | (val << (BitCount - r));
            }

            ///------ rotate and shift combination
            inline T Roll(T &val, const uint8_t* r)
            {
                return ror(val, r[0]) ^ ror(val, r[1]) ^ (val >> r[2]);
            }

            ///------ compression function
            inline void Compress(T &a, T &b, T &c, T &d, T &e, T &f, T &g, T &h, T &x, T const &y)
            {
                h += (ror(e, sr[0]) ^ ror(e, sr[1]) ^ ror(e, sr[2])) + ((e & (f ^ g)) ^ g) + x + y;
                d += h;
                h += (ror(a, sr[3]) ^ ror(a, sr[4]) ^ ror(a, sr[5])) + ((a & (b | c)) | (b & c));
            }

            ///------ compress & digest process of message chunks
            inline void Digest(T* state, const uint8_t* block)
            {
                T   m[8], schedule[Rounds] = {};
                std::memcpy(m, state, BitCount);        /// copy state into temporary array m
                for (int i = 0; i < BlockSize; i++)     /// copy chunk into first 16 words of schedule
                {
                    (schedule[i / sizeof(T)] <<= 8) |= T(block[i]);
                }
                for (int i = 16; i < Rounds; i++)       /// extend
                {
                    schedule[i] = schedule[i - 16] + schedule[i - 7]
                        + Roll(schedule[i - 15], sr + 6) + Roll(schedule[i - 2], sr + 9);
                }
                for (int i = 0; i < Rounds; i++)
                {
                    Compress(m[-i & 7], m[(1 - i) & 7], m[(2 - i) & 7], m[(3 - i) & 7], m[(4 - i) & 7],
                        m[(5 - i) & 7], m[(6 - i) & 7], m[(7 - i) & 7], schedule[i], round_table[i]);
                }
                for (int i = 0; i < 8; i++) state[i] += m[i];
            }

            ///------ padding the last block and finalizing the hash
            inline void Finalize(uint8_t* block, uint64_t size)
            {
                size_t rem = size & (BlockSize - 1);
                block[rem++] = 0x80;
                std::memset(block + rem, 0, BlockSize - rem);
                if (rem > BlockSize - 2 * sizeof(T))
                {
                    Digest(num, block);
                    std::memset(block, 0, BlockSize - 8);
                }
                for (size_t i = 0; i < 8; i++)
                {
                    block[BlockSize - 1 - i] = size << 3 >> (i * 8) & 0xFF;
                }
                Digest(num, block);
                for (size_t i = 0; i < BitCount; i++)
                {
                    bytes[i] = num[i / sizeof(T)] >> (~i % sizeof(T) * 8) & 0xFF;
                }
            }

            ///------ Full message hasher
            void message_hash(const void* message, const size_t &len)
            {
                std::memcpy(num, init_vector, BitCount);
                uint8_t *block = new uint8_t[BlockSize],
                        *mptr = (uint8_t*)message;
                size_t n = len / BlockSize;     /// number of successive chunks
                while (n--)
                {
                    Digest(num, mptr);
                    mptr += BlockSize;
                }
                std::memcpy(block, mptr, len % BlockSize);   /// last chunk
                Finalize(block, len);
            }

            ///------ File hasher
            void file_hash(const std::string &path, const char* filetype)
            {
                struct stat64 st;
                if (stat64(path.c_str(), &st) != 0) throw std::exception();   /// file not found

                std::memcpy(num, init_vector, BitCount);
                uint8_t block[BlockSize];
                FILE* fi = std::fopen(path.c_str(), filetype);
                while (std::fread(block, 1, BlockSize, fi) == BlockSize)
                {
                    Digest(num, block);
                }
                std::fclose(fi);
                Finalize(block, st.st_size);
            }

        public:
            ///------ hash of string
            static hashdata calculate(const std::string &str)
            {
                general_sha2 sh;
                sh.message_hash(str.c_str(), str.size());
                return hashdata(sh.bytes, Hash_Size / 8);
            }

            ///------ hash of file
            static hashdata file(const std::string &path, bool binary = true)
            {
                general_sha2 sh;
                sh.file_hash(path, binary ? "rb" : "r");
                return hashdata(sh.bytes, Hash_Size / 8);
            }

            ///------ hash result for a block of data
            static hashdata calculate(void* data, const size_t datasize)
            {
                general_sha2 sh;
                sh.message_hash(data, datasize);
                return hashdata(sh.bytes, Hash_Size / 8);
            }
        };
    }

    typedef templates::general_sha2 <uint32_t, templates::SHA_256, 256>     SHA256;
    typedef templates::general_sha2 <uint32_t, templates::SHA_224, 224>     SHA224;
    typedef templates::general_sha2 <uint64_t, templates::SHA_512, 512>     SHA512;
    typedef templates::general_sha2 <uint64_t, templates::SHA_384, 384>     SHA384;
    typedef templates::general_sha2 <uint64_t, templates::SHA_512_256, 256> SHA512_256;
    typedef templates::general_sha2 <uint64_t, templates::SHA_512_224, 224> SHA512_224;
    // typedef templates::general_sha2 <uint64_t, templates::SHA_512_xxx, xxx>  SHA512_xxx;
}

#endif // SHA2_h___
