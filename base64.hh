#ifndef BASE64_h___
#define BASE64_h___

#include <string>
#include <cstring>

static const char* B64chars
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int B64index[256] =
{
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  62, 63, 62, 62, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,  0,  0,  0,  0,  0,
    0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,  63,
    0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

std::string b64encode(const void* data, const size_t len)
{
    size_t j = 0, pad = len % 3;
    const size_t Len = len - pad;
    std::string str64(Len / 3 + int(pad > 0) << 2, '=');
    unsigned char *dptr = (unsigned char*)data,
                  *sptr = (unsigned char*)str64.c_str();

    for(size_t i = 0; i < Len; i += 3)
    {
        int n = int(dptr[i]) << 16 | int(dptr[i + 1]) << 8 | dptr[i + 2];
        sptr[j++] = B64chars[n >> 18];
        sptr[j++] = B64chars[n >> 12 & 0x3F];
        sptr[j++] = B64chars[n >> 6 & 0x3F];
        sptr[j++] = B64chars[n & 0x3F];
    }
    if(pad)  /// set padding
    {
        int n = --pad ? int(dptr[Len]) << 8 | dptr[Len + 1] : dptr[Len];
        sptr[j++] = B64chars[pad ? n >> 10 & 0x3F : n >> 2];
        sptr[j++] = B64chars[pad ? n >> 4 & 0x03F : n << 4 & 0x3F];
        sptr[j++] = pad ? B64chars[n << 2 & 0x3F] : '=';
    }
    return str64;
}

std::string b64decode(const void* data, const size_t len)
{
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    std::string str(L / 4 * 3 + pad, '\0');

    for(size_t i = 0, j = 0; i < L; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if(pad)
    {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        str[str.size() - 1] = n >> 16;

        if(len > L + 2 && p[L + 2] != '=')
        {
            n |= B64index[p[L + 2]] << 6;
            str.push_back(n >> 8 & 0xFF);
        }
    }
    return str;
}

std::string b64decode(const std::string& str64)
{
    return b64decode(str64.c_str(), str64.size());
}
#endif  // BASE64_h___