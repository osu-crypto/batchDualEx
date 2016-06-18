#include "cryptopp/osrng.h"
#include "Crypto/PRNG.h"
#include "OT/Math/Zp_Data.h"
#include <stdio.h>

#include <iostream>
using namespace std;

namespace libBDX
{

	PRNG::PRNG()
	{
	}

	//void PRNG::ReSeed()
	//{
	//	block b;
	//	CryptoPP::OS_GenerateRandomBlock(false, b.m128i_u8, sizeof(block));
	//	SetSeed(b);
	//}


	void PRNG::SetSeed(const block& block)
	{
		seed = block;
		AES128::EncKeyGen(seed, mKeyShedule);
		memset(state, 0, SEED_SIZE*sizeof(u8));
		next();
	}


	void PRNG::print_state() const
	{
		int i;
		for (i = 0; i < SEED_SIZE; i++)
		{
			if (ByteArray(seed)[i] < 10) { cout << "0"; }
			cout << hex << (int)ByteArray(seed)[i];
		}
		cout << "\t";
		for (i = 0; i < RAND_SIZE; i++)
		{
			if (random[i] < 10) { cout << "0"; }
			cout << hex << (int)random[i];
		}
		cout << "\t";
		for (i = 0; i < SEED_SIZE; i++)
		{
			if (state[i] < 10) { cout << "0"; }
			cout << hex << (int)state[i];
		}
		cout << " " << dec << cnt << " : ";
	}


	void PRNG::hash()
	{
#ifndef USE_AES
		// Hash seed to get a random value
		blk_SHA_CTX ctx;
		blk_SHA1_Init(&ctx);
		blk_SHA1_Update(&ctx, state, SEED_SIZE);
		blk_SHA1_Final(random, &ctx);
#else
		//if (useC)
		//{
		//	aes_encrypt(random, state, KeyScheduleC);
		//}
		//else
		//{
		//	aes_encrypt(random, state, KeySchedule);
		//}

		AES128::EcbEncBlock(mKeyShedule, *(block*)state, *(block*)random);

#endif
		// This is a new random value so we have not used any of it yet
		cnt = 0;
	}



	void PRNG::next()
	{
		// Increment state
		int i = 0;
		state[i] = state[i] + 1;
		while (i < (SEED_SIZE - 1) && state[i] == 0)
		{
			i++;
			state[i] = state[i] + 1;
		}
		hash();
	}


	__m128i PRNG::get_block()
	{
		__m128i block;
		get_u8s((u8*)&block, sizeof(block));
		//block.m128i_u32[0] = get_uint();
		//block.m128i_u32[1] = get_uint();
		//block.m128i_u32[2] = get_uint();
		//block.m128i_u32[3] = get_uint();

		return block;
	}

	double PRNG::get_double()
	{
		// We need four bytes of randomness
		if (cnt > RAND_SIZE - 4) { next(); }
		unsigned int a0 = random[cnt], a1 = random[cnt + 1], a2 = random[cnt + 2], a3 = random[cnt + 3];
		double ans = (a0 + (a1 << 8) + (a2 << 16) + (a3 << 24));
		cnt = cnt + 4;
		unsigned int den = 0xFFFFFFFF;
		ans = ans / den;
		//print_state(); cout << " DBLE " <<  ans << endl;
		return ans;
	}


	unsigned int PRNG::get_uint()
	{
		// We need four bytes of randomness
		if (cnt > RAND_SIZE - 4) { next(); }
		unsigned int a0 = random[cnt], a1 = random[cnt + 1], a2 = random[cnt + 2], a3 = random[cnt + 3];
		cnt = cnt + 4;
		unsigned int ans = (a0 + (a1 << 8) + (a2 << 16) + (a3 << 24));
		// print_state(); cout << " UINT " << ans << endl;
		return ans;
	}



	unsigned char PRNG::get_uchar()
	{
		if (cnt >= RAND_SIZE) { next(); }
		unsigned char ans = random[cnt];
		cnt++;
		// print_state(); cout << " UCHA " << (int) ans << endl;
		return ans;
	}


	void PRNG::get_ByteStream(ByteStream& ans, u64 len)
	{
		ans.reserve(len);
		for (u64 i = 0; i < len; i++)
		{
			ans.data()[i] = get_uchar();
		}
		ans.mWriteHead = len;
		ans.mReadHead = 0;
	}


	void PRNG::get_u8s(u8* ans, u64 len)
	{
		u64 pos = 0;
		while (len)
		{
			u64 step = std::min(len, RAND_SIZE - cnt);
			memcpy(ans + pos, random + cnt, step);
			pos += step;
			len -= step;
			cnt += step;
			if (cnt == RAND_SIZE)
				next();
		}
	}


	//bigint PRNG::randomBnd(const bigint& B)
	//{
	//	bigint x;
	//	// Hash the seed again and again until we have a lot of len bytes
	//	int len = ((2 * numBytes(B)) / RAND_SIZE + 1)*RAND_SIZE;
	//	u8 *bytes = new u8[len];
	//	if (cnt != 0) { next(); }
	//	for (int i = 0; i < len / RAND_SIZE; i++)
	//	{
	//		memcpy(bytes + RAND_SIZE*i, random, RAND_SIZE*sizeof(u8));
	//		next();
	//	}
	//	bigintFromBytes(x, bytes, len);
	//	x = x%B;
	//	delete[] bytes;
	//	return x;
	//}




	//modp PRNG::get_modp(const Zp_Data& ZpD)
	//{
	//	bigint x = randomBnd(ZpD.pr);
	//	modp y;
	//	to_modp(y, x, ZpD);
	//	//print_state(); cout << " MODP " << to_bigint(y,ZpD) << " mod " << ZpD.pr << endl;
	//	return y;
	//}

}
