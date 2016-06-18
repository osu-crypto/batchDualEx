#pragma once
#include "OT/Math/modp.h"
//#include "OT/Extention/Tools/sha1.h"
//#include "OT/Extention/Tools/aes.h"
#include "Common/Defines.h"
#include "Crypto/AES.h"
#include "Crypto/sha1.h"

#define USE_AES

#ifndef USE_AES
#define SEED_SIZE   HASH_SIZE
#define RAND_SIZE   HASH_SIZE
#else
#define SEED_SIZE   AES_BLK_SIZE
#define RAND_SIZE   AES_BLK_SIZE
#endif


/* This basically defines a randomness expander, if using
 * as a real PRG on an input stream you should first collapse
 * the input stream down to a SEED, say via CBC-MAC (under 0 key)
 * or via a hash
 */

 // __attribute__ is needed to get the sse instructions to avoid
 //  seg faulting.

namespace libBDX
{

	class PRNG
	{
		block seed;
		ALIGNED(u8 state[SEED_SIZE], 16);
		ALIGNED(u8 random[RAND_SIZE], 16);

#ifdef USE_AES
		//bool useC;

		// Two types of key schedule for the different implementations 
		// of AES
		//u32  KeyScheduleC[44];
		//ALIGNED(u8 KeySchedule[176], 16);

		AES128::Key mKeyShedule;
#endif

		u64 cnt;    // How many bytes of the current random value have been used

		void hash(); // Hashes state to random and sets cnt=0
		void next();

	public:

		PRNG();
		PRNG(const block& seed)
		{
			SetSeed(seed);
		}
		PRNG(const PRNG&) = delete;
		
		// For debugging
		void print_state() const;

		// Set seed from dev/random
		//void ReSeed();

		// Set seed from array
		void SetSeed(const block& b);

		__m128i get_block();
		double get_double();
		u8 get_uchar();
		u32 get_uint();
		u8 get_bit() { return get_uchar() & 1; }
		//bigint randomBnd(const bigint& B);
		//modp get_modp(const Zp_Data& ZpD);
		u64 get_u64()
		{
			u64 a = get_uint();
			a <<= 32;
			a += get_uint();
			return a;
		}
		void get_ByteStream(ByteStream& ans, u64 len);
		void get_u8s(u8* ans, u64 len);

		const block get_seed() const
		{
			return seed;
		}


		typedef u64 result_type;
		static u64 min() { return 0; }
		static u64 max() { return (u64)-1; }
		u64 operator()() {
			return get_u64();
			// generate a random number in the range [0, 42]
		}
	};
}
