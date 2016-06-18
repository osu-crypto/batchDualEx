#pragma once

/*
 * SHA1 routine optimized to do u64 accesses rather than byte accesses,
 * and to avoid unnecessary copies into the context array.
 *
 * This was initially based on the Mozilla SHA1 implementation, although
 * none of the original Mozilla code remains.
 */
#include "Common/Defines.h"
#include "cryptopp/sha.h"

namespace libBDX {
	class SHA1
	{
	public:
		static const u64 HashSize = 20;
		SHA1() { Reset(); }

		//u64 mSize;
		//u32 mH[5];
		//u32 mW[16];

		inline void Reset()
		{
			mSha.Restart();
		}
		inline void Update(const u8* dataIn, u64 length)
		{
			mSha.Update(dataIn, length);
		}
		inline void Update(const block& blk)
		{
			Update(ByteArray(blk), sizeof(block));
		}
		inline void Final(u8* DataOut)
		{
			mSha.Final(DataOut);
		}

	private:
		//void Block(const u32* data);
		CryptoPP::SHA1 mSha;

	};
	//u64	SHA1::HashSize(20);

	//void blk_SHA1_Init(blk_SHA_CTX *ctx);
	//void blk_SHA1_Update(blk_SHA_CTX *ctx, const void *dataIn, unsigned long len);
	//void blk_SHA1_Final(unsigned char hashout[20], blk_SHA_CTX *ctx);
	//
	//#define git_SHA_CTX	blk_SHA_CTX
	//#define git_SHA1_Init	blk_SHA1_Init
	//#define git_SHA1_Update	blk_SHA1_Update
	//#define git_SHA1_Final	blk_SHA1_Final

}
