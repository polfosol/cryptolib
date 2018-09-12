#ifndef BASE64_h___
#define BASE64_h___

#include <string>

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

const std::string b64encode(const void* data, const size_t &len)
{
    unsigned char *p = (unsigned char*)data,
                *str = new unsigned char[(len + 2) / 3 * 4];
    size_t j = 0, pad = len % 3;
    const size_t Len = len - pad;

    for(size_t i = 0; i < Len; i += 3)
    {
        int n = int(p[i]) << 16 | int(p[i + 1]) << 8 | p[i + 2];
        str[j++] = B64chars[n >> 18];
        str[j++] = B64chars[n >> 12 & 0x3F];
        str[j++] = B64chars[n >> 6 & 0x3F];
        str[j++] = B64chars[n & 0x3F];
    }
    if(pad)  /// set padding
    {
        int n = --pad ? int(p[Len]) << 8 | p[Len + 1] : p[Len];
        str[j++] = B64chars[pad ? n >> 10 & 0x3F : n >> 2];
        str[j++] = B64chars[pad ? n >> 4 & 0x03F : n << 4 & 0x3F];
        str[j++] = pad ? B64chars[n << 2 & 0x3F] : '=';
        str[j++] = '=';
    }
    return std::string((const char*) str, j);
}

const std::string b64decode(const void* data, const size_t &len)
{
    unsigned char *p = (unsigned char*)data,
                *str = new unsigned char[(len + 3) / 4 * 3];
    size_t j = 0, pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t Len = (len - pad) / 4 << 2; 

    for(size_t i = 0; i < Len; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if(pad)
    {
        int n = B64index[p[Len]] << 18 | B64index[p[Len + 1]] << 12;
        str[j++] = n >> 16;
        if(len > Len + 2 && p[Len + 2] != '=')
        {
            n |= B64index[p[Len + 2]] << 6;
            str[j++] = n >> 8 & 0xFF;
        }
    }
    return std::string((const char*) str, j);
}

std::string b64encode(const std::string& str)
{
    return b64encode(str.c_str(), str.size());
}

std::string b64decode(const std::string& str64)
{
    return b64decode(str64.c_str(), str64.size());
}

#endif  // BASE64_h___
