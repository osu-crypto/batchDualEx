#pragma once
#include "Common/Defines.h"
#define AES_DECRYPTION
#include <wmmintrin.h>

namespace libBDX {

#define AES_BLK_SIZE 16




	class AES128
	{


	public:
		struct  Key
		{
			block mRoundKey[11];
		};

		static const Key mAesFixedKey;

		static void EncKeyGen(const block& userKey, Key& key)
		{

			key.mRoundKey[0] = userKey;
			key.mRoundKey[1] = Expansion(key.mRoundKey[0], _mm_aeskeygenassist_si128(key.mRoundKey[0], 0x01));
			key.mRoundKey[2] = Expansion(key.mRoundKey[1], _mm_aeskeygenassist_si128(key.mRoundKey[1], 0x02));
			key.mRoundKey[3] = Expansion(key.mRoundKey[2], _mm_aeskeygenassist_si128(key.mRoundKey[2], 0x04));
			key.mRoundKey[4] = Expansion(key.mRoundKey[3], _mm_aeskeygenassist_si128(key.mRoundKey[3], 0x08));
			key.mRoundKey[5] = Expansion(key.mRoundKey[4], _mm_aeskeygenassist_si128(key.mRoundKey[4], 0x10));
			key.mRoundKey[6] = Expansion(key.mRoundKey[5], _mm_aeskeygenassist_si128(key.mRoundKey[5], 0x20));
			key.mRoundKey[7] = Expansion(key.mRoundKey[6], _mm_aeskeygenassist_si128(key.mRoundKey[6], 0x40));
			key.mRoundKey[8] = Expansion(key.mRoundKey[7], _mm_aeskeygenassist_si128(key.mRoundKey[7], 0x80));
			key.mRoundKey[9] = Expansion(key.mRoundKey[8], _mm_aeskeygenassist_si128(key.mRoundKey[8], 0x1B));
			key.mRoundKey[10] = Expansion(key.mRoundKey[9], _mm_aeskeygenassist_si128(key.mRoundKey[9], 0x36));
		}

		static inline void EcbEncBlock(const Key& key, const block& src, block& dest)
		{
			//AES128::EcbEncBlock(key, &src, &dest); 
			dest = _mm_xor_si128(src, key.mRoundKey[0]);
			dest = _mm_aesenc_si128(dest, key.mRoundKey[1]);
			dest = _mm_aesenc_si128(dest, key.mRoundKey[2]);
			dest = _mm_aesenc_si128(dest, key.mRoundKey[3]);
			dest = _mm_aesenc_si128(dest, key.mRoundKey[4]);
			dest = _mm_aesenc_si128(dest, key.mRoundKey[5]);
			dest = _mm_aesenc_si128(dest, key.mRoundKey[6]);
			dest = _mm_aesenc_si128(dest, key.mRoundKey[7]);
			dest = _mm_aesenc_si128(dest, key.mRoundKey[8]);
			dest = _mm_aesenc_si128(dest, key.mRoundKey[9]);
			dest = _mm_aesenclast_si128(dest, key.mRoundKey[10]);
		}

		static void EcbEncFourBlocks(const Key& key, const block* src, block* dest)
		{

			dest[0] = _mm_xor_si128(src[0], key.mRoundKey[0]);
			dest[1] = _mm_xor_si128(src[1], key.mRoundKey[0]);
			dest[2] = _mm_xor_si128(src[2], key.mRoundKey[0]);
			dest[3] = _mm_xor_si128(src[3], key.mRoundKey[0]);

			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[1]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[1]);
			dest[2] = _mm_aesenc_si128(dest[2], key.mRoundKey[1]);
			dest[3] = _mm_aesenc_si128(dest[3], key.mRoundKey[1]);

			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[2]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[2]);
			dest[2] = _mm_aesenc_si128(dest[2], key.mRoundKey[2]);
			dest[3] = _mm_aesenc_si128(dest[3], key.mRoundKey[2]);

			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[3]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[3]);
			dest[2] = _mm_aesenc_si128(dest[2], key.mRoundKey[3]);
			dest[3] = _mm_aesenc_si128(dest[3], key.mRoundKey[3]);

			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[4]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[4]);
			dest[2] = _mm_aesenc_si128(dest[2], key.mRoundKey[4]);
			dest[3] = _mm_aesenc_si128(dest[3], key.mRoundKey[4]);

			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[5]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[5]);
			dest[2] = _mm_aesenc_si128(dest[2], key.mRoundKey[5]);
			dest[3] = _mm_aesenc_si128(dest[3], key.mRoundKey[5]);

			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[6]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[6]);
			dest[2] = _mm_aesenc_si128(dest[2], key.mRoundKey[6]);
			dest[3] = _mm_aesenc_si128(dest[3], key.mRoundKey[6]);

			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[7]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[7]);
			dest[2] = _mm_aesenc_si128(dest[2], key.mRoundKey[7]);
			dest[3] = _mm_aesenc_si128(dest[3], key.mRoundKey[7]);

			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[8]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[8]);
			dest[2] = _mm_aesenc_si128(dest[2], key.mRoundKey[8]);
			dest[3] = _mm_aesenc_si128(dest[3], key.mRoundKey[8]);

			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[9]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[9]);
			dest[2] = _mm_aesenc_si128(dest[2], key.mRoundKey[9]);
			dest[3] = _mm_aesenc_si128(dest[3], key.mRoundKey[9]);

			dest[0] = _mm_aesenclast_si128(dest[0], key.mRoundKey[10]);
			dest[1] = _mm_aesenclast_si128(dest[1], key.mRoundKey[10]);
			dest[2] = _mm_aesenclast_si128(dest[2], key.mRoundKey[10]);
			dest[3] = _mm_aesenclast_si128(dest[3], key.mRoundKey[10]); 
		}



		static void EcbEncTwoBlocks(const Key& key, const block* src, block* dest)
		{
			dest[0] = _mm_xor_si128(src[0], key.mRoundKey[0]);
			dest[1] = _mm_xor_si128(src[1], key.mRoundKey[0]);
			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[1]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[1]);
			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[2]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[2]);
			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[3]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[3]);
			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[4]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[4]);
			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[5]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[5]);
			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[6]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[6]);
			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[7]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[7]);
			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[8]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[8]);
			dest[0] = _mm_aesenc_si128(dest[0], key.mRoundKey[9]);
			dest[1] = _mm_aesenc_si128(dest[1], key.mRoundKey[9]);
			dest[0] = _mm_aesenclast_si128(dest[0], key.mRoundKey[10]);
			dest[1] = _mm_aesenclast_si128(dest[1], key.mRoundKey[10]);
			 
		}
		// 
		//template<u32 blocks>
		//static void EcbEncBlocks(const Key& key, const block* src, block* dest)
		//{
		//	// compiler will unroll the loop for each block.
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_xor_si128(src[i], key.mRoundKey[0]);   });
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[1]);   });
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[2]);   });
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[3]);   });
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[4]);   });
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[5]);   });
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[6]);   });
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[7]);   });
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[8]);   });
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[9]);   });
		//	Unroll<blocks>::call([&](u32 i) { dest[i] = _mm_aesenclast_si128(dest[i], key.mRoundKey[10]); });
		//}

		static void EcbEncBlocks(const Key& key, const block* src, block* dest, u64 size)
		{

			const u32 unrollCount = 8;
			u32 mainLoopCount = (u32)size / unrollCount;
			//u32 remainderCount = (u32)size % unrollCount;

			for (u32 j = 0, k = 0; j < mainLoopCount; ++j, k += unrollCount)
			{
				// compiler will unroll this by a factor of unrollCount.
				dest[k + 0] = _mm_xor_si128(src[k + 0], key.mRoundKey[0]);
				dest[k + 1] = _mm_xor_si128(src[k + 1], key.mRoundKey[0]);
				dest[k + 2] = _mm_xor_si128(src[k + 2], key.mRoundKey[0]);
				dest[k + 3] = _mm_xor_si128(src[k + 3], key.mRoundKey[0]);
				dest[k + 4] = _mm_xor_si128(src[k + 4], key.mRoundKey[0]);
				dest[k + 5] = _mm_xor_si128(src[k + 5], key.mRoundKey[0]);
				dest[k + 6] = _mm_xor_si128(src[k + 6], key.mRoundKey[0]);
				dest[k + 7] = _mm_xor_si128(src[k + 7], key.mRoundKey[0]);

				dest[k + 0] = _mm_aesenc_si128(dest[k + 0], key.mRoundKey[1]);
				dest[k + 1] = _mm_aesenc_si128(dest[k + 1], key.mRoundKey[1]);
				dest[k + 2] = _mm_aesenc_si128(dest[k + 2], key.mRoundKey[1]);
				dest[k + 3] = _mm_aesenc_si128(dest[k + 3], key.mRoundKey[1]);
				dest[k + 4] = _mm_aesenc_si128(dest[k + 4], key.mRoundKey[1]);
				dest[k + 5] = _mm_aesenc_si128(dest[k + 5], key.mRoundKey[1]);
				dest[k + 6] = _mm_aesenc_si128(dest[k + 6], key.mRoundKey[1]);
				dest[k + 7] = _mm_aesenc_si128(dest[k + 7], key.mRoundKey[1]);

				dest[k + 0] = _mm_aesenc_si128(dest[k + 0], key.mRoundKey[2]);
				dest[k + 1] = _mm_aesenc_si128(dest[k + 1], key.mRoundKey[2]);
				dest[k + 2] = _mm_aesenc_si128(dest[k + 2], key.mRoundKey[2]);
				dest[k + 3] = _mm_aesenc_si128(dest[k + 3], key.mRoundKey[2]);
				dest[k + 4] = _mm_aesenc_si128(dest[k + 4], key.mRoundKey[2]);
				dest[k + 5] = _mm_aesenc_si128(dest[k + 5], key.mRoundKey[2]);
				dest[k + 6] = _mm_aesenc_si128(dest[k + 6], key.mRoundKey[2]);
				dest[k + 7] = _mm_aesenc_si128(dest[k + 7], key.mRoundKey[2]);

				dest[k + 0] = _mm_aesenc_si128(dest[k + 0], key.mRoundKey[3]);
				dest[k + 1] = _mm_aesenc_si128(dest[k + 1], key.mRoundKey[3]);
				dest[k + 2] = _mm_aesenc_si128(dest[k + 2], key.mRoundKey[3]);
				dest[k + 3] = _mm_aesenc_si128(dest[k + 3], key.mRoundKey[3]);
				dest[k + 4] = _mm_aesenc_si128(dest[k + 4], key.mRoundKey[3]);
				dest[k + 5] = _mm_aesenc_si128(dest[k + 5], key.mRoundKey[3]);
				dest[k + 6] = _mm_aesenc_si128(dest[k + 6], key.mRoundKey[3]);
				dest[k + 7] = _mm_aesenc_si128(dest[k + 7], key.mRoundKey[3]);

				dest[k + 0] = _mm_aesenc_si128(dest[k + 0], key.mRoundKey[4]);
				dest[k + 1] = _mm_aesenc_si128(dest[k + 1], key.mRoundKey[4]);
				dest[k + 2] = _mm_aesenc_si128(dest[k + 2], key.mRoundKey[4]);
				dest[k + 3] = _mm_aesenc_si128(dest[k + 3], key.mRoundKey[4]);
				dest[k + 4] = _mm_aesenc_si128(dest[k + 4], key.mRoundKey[4]);
				dest[k + 5] = _mm_aesenc_si128(dest[k + 5], key.mRoundKey[4]);
				dest[k + 6] = _mm_aesenc_si128(dest[k + 6], key.mRoundKey[4]);
				dest[k + 7] = _mm_aesenc_si128(dest[k + 7], key.mRoundKey[4]);

				dest[k + 0] = _mm_aesenc_si128(dest[k + 0], key.mRoundKey[5]);
				dest[k + 1] = _mm_aesenc_si128(dest[k + 1], key.mRoundKey[5]);
				dest[k + 2] = _mm_aesenc_si128(dest[k + 2], key.mRoundKey[5]);
				dest[k + 3] = _mm_aesenc_si128(dest[k + 3], key.mRoundKey[5]);
				dest[k + 4] = _mm_aesenc_si128(dest[k + 4], key.mRoundKey[5]);
				dest[k + 5] = _mm_aesenc_si128(dest[k + 5], key.mRoundKey[5]);
				dest[k + 6] = _mm_aesenc_si128(dest[k + 6], key.mRoundKey[5]);
				dest[k + 7] = _mm_aesenc_si128(dest[k + 7], key.mRoundKey[5]);

				dest[k + 0] = _mm_aesenc_si128(dest[k + 0], key.mRoundKey[6]);
				dest[k + 1] = _mm_aesenc_si128(dest[k + 1], key.mRoundKey[6]);
				dest[k + 2] = _mm_aesenc_si128(dest[k + 2], key.mRoundKey[6]);
				dest[k + 3] = _mm_aesenc_si128(dest[k + 3], key.mRoundKey[6]);
				dest[k + 4] = _mm_aesenc_si128(dest[k + 4], key.mRoundKey[6]);
				dest[k + 5] = _mm_aesenc_si128(dest[k + 5], key.mRoundKey[6]);
				dest[k + 6] = _mm_aesenc_si128(dest[k + 6], key.mRoundKey[6]);
				dest[k + 7] = _mm_aesenc_si128(dest[k + 7], key.mRoundKey[6]);

				dest[k + 0] = _mm_aesenc_si128(dest[k + 0], key.mRoundKey[7]);
				dest[k + 1] = _mm_aesenc_si128(dest[k + 1], key.mRoundKey[7]);
				dest[k + 2] = _mm_aesenc_si128(dest[k + 2], key.mRoundKey[7]);
				dest[k + 3] = _mm_aesenc_si128(dest[k + 3], key.mRoundKey[7]);
				dest[k + 4] = _mm_aesenc_si128(dest[k + 4], key.mRoundKey[7]);
				dest[k + 5] = _mm_aesenc_si128(dest[k + 5], key.mRoundKey[7]);
				dest[k + 6] = _mm_aesenc_si128(dest[k + 6], key.mRoundKey[7]);
				dest[k + 7] = _mm_aesenc_si128(dest[k + 7], key.mRoundKey[7]);

				dest[k + 0] = _mm_aesenc_si128(dest[k + 0], key.mRoundKey[8]);
				dest[k + 1] = _mm_aesenc_si128(dest[k + 1], key.mRoundKey[8]);
				dest[k + 2] = _mm_aesenc_si128(dest[k + 2], key.mRoundKey[8]);
				dest[k + 3] = _mm_aesenc_si128(dest[k + 3], key.mRoundKey[8]);
				dest[k + 4] = _mm_aesenc_si128(dest[k + 4], key.mRoundKey[8]);
				dest[k + 5] = _mm_aesenc_si128(dest[k + 5], key.mRoundKey[8]);
				dest[k + 6] = _mm_aesenc_si128(dest[k + 6], key.mRoundKey[8]);
				dest[k + 7] = _mm_aesenc_si128(dest[k + 7], key.mRoundKey[8]);

				dest[k + 0] = _mm_aesenc_si128(dest[k + 0], key.mRoundKey[9]);
				dest[k + 1] = _mm_aesenc_si128(dest[k + 1], key.mRoundKey[9]);
				dest[k + 2] = _mm_aesenc_si128(dest[k + 2], key.mRoundKey[9]);
				dest[k + 3] = _mm_aesenc_si128(dest[k + 3], key.mRoundKey[9]);
				dest[k + 4] = _mm_aesenc_si128(dest[k + 4], key.mRoundKey[9]);
				dest[k + 5] = _mm_aesenc_si128(dest[k + 5], key.mRoundKey[9]);
				dest[k + 6] = _mm_aesenc_si128(dest[k + 6], key.mRoundKey[9]);
				dest[k + 7] = _mm_aesenc_si128(dest[k + 7], key.mRoundKey[9]);

				dest[k + 0] = _mm_aesenclast_si128(dest[k + 0], key.mRoundKey[10]);
				dest[k + 1] = _mm_aesenclast_si128(dest[k + 1], key.mRoundKey[10]);
				dest[k + 2] = _mm_aesenclast_si128(dest[k + 2], key.mRoundKey[10]);
				dest[k + 3] = _mm_aesenclast_si128(dest[k + 3], key.mRoundKey[10]);
				dest[k + 4] = _mm_aesenclast_si128(dest[k + 4], key.mRoundKey[10]);
				dest[k + 5] = _mm_aesenclast_si128(dest[k + 5], key.mRoundKey[10]);
				dest[k + 6] = _mm_aesenclast_si128(dest[k + 6], key.mRoundKey[10]);
				dest[k + 7] = _mm_aesenclast_si128(dest[k + 7], key.mRoundKey[10]);

				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_xor_si128(src[k + i], key.mRoundKey[0]);          });
				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_aesenc_si128(dest[k + i], key.mRoundKey[1]);      });
				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_aesenc_si128(dest[k + i], key.mRoundKey[2]);      });
				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_aesenc_si128(dest[k + i], key.mRoundKey[3]);      });
				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_aesenc_si128(dest[k + i], key.mRoundKey[4]);      });
				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_aesenc_si128(dest[k + i], key.mRoundKey[5]);      });
				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_aesenc_si128(dest[k + i], key.mRoundKey[6]);      });
				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_aesenc_si128(dest[k + i], key.mRoundKey[7]);      });
				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_aesenc_si128(dest[k + i], key.mRoundKey[8]);      });
				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_aesenc_si128(dest[k + i], key.mRoundKey[9]);      });
				//Unroll<unrollCount>::call([&](u32 i) { dest[k + i] = _mm_aesenclast_si128(dest[k + i], key.mRoundKey[10]); });
			}

			// encrypt the remaining blocks
			for (u32 i = mainLoopCount * unrollCount; i < size; ++i)
			{
				dest[i] = _mm_xor_si128(src[i], key.mRoundKey[0]);
				dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[1]);
				dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[2]);
				dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[3]);
				dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[4]);
				dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[5]);
				dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[6]);
				dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[7]);
				dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[8]);
				dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[9]);
				dest[i] = _mm_aesenclast_si128(dest[i], key.mRoundKey[10]);
			}
		}

		static void DecKeyGen(const block& userKey, Key& key)
		{
			const block& v0 = userKey;
			const block  v1 = Expansion(v0, _mm_aeskeygenassist_si128(v0, 0x01));
			const block  v2 = Expansion(v1, _mm_aeskeygenassist_si128(v1, 0x02));
			const block  v3 = Expansion(v2, _mm_aeskeygenassist_si128(v2, 0x04));
			const block  v4 = Expansion(v3, _mm_aeskeygenassist_si128(v3, 0x08));
			const block  v5 = Expansion(v4, _mm_aeskeygenassist_si128(v4, 0x10));
			const block  v6 = Expansion(v5, _mm_aeskeygenassist_si128(v5, 0x20));
			const block  v7 = Expansion(v6, _mm_aeskeygenassist_si128(v6, 0x40));
			const block  v8 = Expansion(v7, _mm_aeskeygenassist_si128(v7, 0x80));
			const block  v9 = Expansion(v8, _mm_aeskeygenassist_si128(v8, 0x1B));
			const block  v10 = Expansion(v9, _mm_aeskeygenassist_si128(v9, 0x36));

			_mm_storeu_si128(key.mRoundKey, v10);
			_mm_storeu_si128(key.mRoundKey + 1, _mm_aesimc_si128(v9));
			_mm_storeu_si128(key.mRoundKey + 2, _mm_aesimc_si128(v8));
			_mm_storeu_si128(key.mRoundKey + 3, _mm_aesimc_si128(v7));
			_mm_storeu_si128(key.mRoundKey + 4, _mm_aesimc_si128(v6));
			_mm_storeu_si128(key.mRoundKey + 5, _mm_aesimc_si128(v5));
			_mm_storeu_si128(key.mRoundKey + 6, _mm_aesimc_si128(v4));
			_mm_storeu_si128(key.mRoundKey + 7, _mm_aesimc_si128(v3));
			_mm_storeu_si128(key.mRoundKey + 8, _mm_aesimc_si128(v2));
			_mm_storeu_si128(key.mRoundKey + 9, _mm_aesimc_si128(v1));
			_mm_storeu_si128(key.mRoundKey + 10, v0);
		}

		static void EcbDecBlock(const Key& key, const block& src, block& dest)
		{

			dest = _mm_xor_si128(src, key.mRoundKey[0]);
			dest = _mm_aesdec_si128(dest, key.mRoundKey[1]);
			dest = _mm_aesdec_si128(dest, key.mRoundKey[2]);
			dest = _mm_aesdec_si128(dest, key.mRoundKey[3]);
			dest = _mm_aesdec_si128(dest, key.mRoundKey[4]);
			dest = _mm_aesdec_si128(dest, key.mRoundKey[5]);
			dest = _mm_aesdec_si128(dest, key.mRoundKey[6]);
			dest = _mm_aesdec_si128(dest, key.mRoundKey[7]);
			dest = _mm_aesdec_si128(dest, key.mRoundKey[8]);
			dest = _mm_aesdec_si128(dest, key.mRoundKey[9]);
			dest = _mm_aesdeclast_si128(dest, key.mRoundKey[10]);

		}

	private:

		static inline block Expansion(block key, block keyRcon)
		{
			keyRcon = _mm_shuffle_epi32(keyRcon, _MM_SHUFFLE(3, 3, 3, 3));
			key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
			key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
			key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
			return _mm_xor_si128(key, keyRcon);
		}
	};

}
