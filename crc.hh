
#ifndef _CRC_HH_
#define _CRC_HH_

#include <cstdio>
#include <string>
#include <stdint.h>


namespace ccrc
{
	namespace templates
	{
		template <typename T> struct crcdata
		{
			T number;
			std::string toHex(const bool lowercase = false)
			{
				std::string s(2 * sizeof(T), '0');
				for (T n = number, i = s.size(); n; n >>= 4)
					s[--i] += (n & 0xF) > 9 ? (n % 16 - 9) | (lowercase ? 48 : 16) : n % 16;

				return s;
			}
		};

		///===================< General CRC calculation template >=======================
		template <typename T, T polynomial, T init_cr, T final_cr>
		class general_crc
		{
		public:
			/// constructor and initializer
			inline general_crc()
			{
				static T table[256];

				/// build CRC lookup table. Skip the loop if already evaluated
				for (int i = 0, b = 0; i < 256 && !table[255]; b = 8, i++)
				{
					table[i] = i;
					while (b--)	table[i] = (table[i] >> 1) ^ (table[i] & 1 ? polynomial : 0);
				}

				result.number = init_cr;
				crc_table = (T const*)(void*)&table[0];
			}

			/// destructor
			virtual ~general_crc(){}

		private:
			/// result of crc
			crcdata <T> result;

			/// pointer to the lookup table
			T const* crc_table;

			/// core function of crc calculation
			void crc_calc(const void* buf, size_t size)
			{
				uint8_t* p = (uint8_t*)buf;

				while (size--)
					result.number = crc_table[(*p++ ^ result.number) & 0xFF] ^ (result.number >> 8);
			}

			enum{ fileBuffer = 0x1000 };	/// 4kB

			/// file crc calculation
			bool crc_file(const std::string& fpath, const bool& bin)
			{
				FILE* fi = bin ? std::fopen(fpath.c_str(), "rb") : std::fopen(fpath.c_str(), "r");
				if (!fi)   return false;

				char block[fileBuffer];
				size_t bytCount;

				while (bytCount = std::fread(block, 1, fileBuffer, fi))
					crc_calc(block, bytCount);

				std::fclose(fi);
				return true;
			}

		public:
			/// crc of string
			static crcdata <T> calculate(const std::string& s)
			{
				general_crc cr;
				cr.crc_calc(s.c_str(), s.size());
				cr.result.number ^= final_cr;
				return cr.result;
			}

			/// crc of file
			static crcdata <T> file(const std::string path, bool binary = true)
			{
				general_crc cr;
				if (cr.crc_file(path, binary))
				{
					cr.result.number ^= final_cr;
					return cr.result;
				}
				return crcdata <T>();
			}

			/// crc of a block of data
			static crcdata <T> calculate(const void* data, size_t size)
			{
				general_crc cr;
				cr.crc_calc(data, size);
				cr.result.number ^= final_cr;
				return cr.result;
			}
		};
	}
}

namespace ccrc
{
	typedef templates::general_crc <uint16_t, 0xA001, 0, 0>		CRC16;
	typedef templates::general_crc <uint32_t, 0xEDB88320U, 0xFFFFFFFF, 0xFFFFFFFF>	CRC32;
	typedef templates::general_crc <uint64_t, 0xC96C5795D7870F42LLU, ~0LL, ~0LL>	CRC64;
}

#endif // _CRC_HH_
