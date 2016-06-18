#include "AES.h"


namespace libBDX{

	const AES128::Key AES128::mAesFixedKey = []()
	{
		AES128::Key key;
		block fixedKey = _mm_set_epi8(36, -100, 50, -22, 92, -26, 49, 9, -82, -86, -51, -96, 98, -20, 29, -13);
		AES128::EncKeyGen(fixedKey, key);
		return key;
	}();

   //void AES128::EncKeyGen(const block& userKey, Key& key)
   //{
   //   key.mRoundKey[0] = userKey;
   //   key.mRoundKey[1] = Expansion(key.mRoundKey[0], _mm_aeskeygenassist_si128(key.mRoundKey[0], 0x01));
   //   key.mRoundKey[2] = Expansion(key.mRoundKey[1], _mm_aeskeygenassist_si128(key.mRoundKey[1], 0x02));
   //   key.mRoundKey[3] = Expansion(key.mRoundKey[2], _mm_aeskeygenassist_si128(key.mRoundKey[2], 0x04));
   //   key.mRoundKey[4] = Expansion(key.mRoundKey[3], _mm_aeskeygenassist_si128(key.mRoundKey[3], 0x08));
   //   key.mRoundKey[5] = Expansion(key.mRoundKey[4], _mm_aeskeygenassist_si128(key.mRoundKey[4], 0x10));
   //   key.mRoundKey[6] = Expansion(key.mRoundKey[5], _mm_aeskeygenassist_si128(key.mRoundKey[5], 0x20));
   //   key.mRoundKey[7] = Expansion(key.mRoundKey[6], _mm_aeskeygenassist_si128(key.mRoundKey[6], 0x40));
   //   key.mRoundKey[8] = Expansion(key.mRoundKey[7], _mm_aeskeygenassist_si128(key.mRoundKey[7], 0x80));
   //   key.mRoundKey[9] = Expansion(key.mRoundKey[8], _mm_aeskeygenassist_si128(key.mRoundKey[8], 0x1B));
   //   key.mRoundKey[10] = Expansion(key.mRoundKey[9], _mm_aeskeygenassist_si128(key.mRoundKey[9], 0x36));
   //}
   //
   //void AES128::EcbEncBlock(const Key& key, const block& src, block& dest)
   //{
   //
   //   //dest = _mm_xor_si128(src, key.mRoundKey[0]); 
   //   //dest = _mm_aesenc_si128(dest, key.mRoundKey[1]);
   //   //dest = _mm_aesenc_si128(dest, key.mRoundKey[2]);
   //   //dest = _mm_aesenc_si128(dest, key.mRoundKey[3]);
   //   //dest = _mm_aesenc_si128(dest, key.mRoundKey[4]);
   //   //dest = _mm_aesenc_si128(dest, key.mRoundKey[5]);
   //   //dest = _mm_aesenc_si128(dest, key.mRoundKey[6]);
   //   //dest = _mm_aesenc_si128(dest, key.mRoundKey[7]);
   //   //dest = _mm_aesenc_si128(dest, key.mRoundKey[8]);
   //   //dest = _mm_aesenc_si128(dest, key.mRoundKey[9]);
   //   //dest = _mm_aesenclast_si128(dest, key.mRoundKey[10]);
   //    
   //}


   //void AES128::EcbEncBlocks(const Key& key, const block* src, block* dest, u64 size)
   //{

   //   const u32 unrollCount = 8;
   //   u32 mainLoopCount = size / unrollCount;
   //   u32 remainderCount = size % unrollCount;

   //   for (u32 j = 0; j < mainLoopCount; ++j)
   //   {
   //      // compiler will unroll this by a factor of unrollCount.
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_xor_si128(src[unrollCount * j + i], key.mRoundKey[0]);   });
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_aesenc_si128(dest[unrollCount * j + i], key.mRoundKey[1]);   });
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_aesenc_si128(dest[unrollCount * j + i], key.mRoundKey[2]);   });
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_aesenc_si128(dest[unrollCount * j + i], key.mRoundKey[3]);   });
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_aesenc_si128(dest[unrollCount * j + i], key.mRoundKey[4]);   });
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_aesenc_si128(dest[unrollCount * j + i], key.mRoundKey[5]);   });
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_aesenc_si128(dest[unrollCount * j + i], key.mRoundKey[6]);   });
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_aesenc_si128(dest[unrollCount * j + i], key.mRoundKey[7]);   });
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_aesenc_si128(dest[unrollCount * j + i], key.mRoundKey[8]);   });
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_aesenc_si128(dest[unrollCount * j + i], key.mRoundKey[9]);   });
   //      Unroll<unrollCount>::call([&](u32 i){ dest[unrollCount * j + i] = _mm_aesenclast_si128(dest[unrollCount * j + i], key.mRoundKey[10]); });
   //   }

   //   // encrypt the remaining blocks
   //   for (u32 i = mainLoopCount * unrollCount; i < size; ++i)
   //   {
   //      dest[i] = _mm_xor_si128(src[i], key.mRoundKey[0]);
   //      dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[1]);
   //      dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[2]);
   //      dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[3]);
   //      dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[4]);
   //      dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[5]);
   //      dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[6]);
   //      dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[7]);
   //      dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[8]);
   //      dest[i] = _mm_aesenc_si128(dest[i], key.mRoundKey[9]);
   //      dest[i] = _mm_aesenclast_si128(dest[i], key.mRoundKey[10]);
   //   }
   //}

//#ifdef AES_DECRYPTION


   //void AES128::DecKeyGen(const block& userKey, Key& key)
   //{
   //   const block& v0 = userKey;
   //   const block  v1 = Expansion(v0, _mm_aeskeygenassist_si128(v0, 0x01));
   //   const block  v2 = Expansion(v1, _mm_aeskeygenassist_si128(v1, 0x02));
   //   const block  v3 = Expansion(v2, _mm_aeskeygenassist_si128(v2, 0x04));
   //   const block  v4 = Expansion(v3, _mm_aeskeygenassist_si128(v3, 0x08));
   //   const block  v5 = Expansion(v4, _mm_aeskeygenassist_si128(v4, 0x10));
   //   const block  v6 = Expansion(v5, _mm_aeskeygenassist_si128(v5, 0x20));
   //   const block  v7 = Expansion(v6, _mm_aeskeygenassist_si128(v6, 0x40));
   //   const block  v8 = Expansion(v7, _mm_aeskeygenassist_si128(v7, 0x80));
   //   const block  v9 = Expansion(v8, _mm_aeskeygenassist_si128(v8, 0x1B));
   //   const block  v10 = Expansion(v9, _mm_aeskeygenassist_si128(v9, 0x36));

   //   _mm_storeu_si128(key.mRoundKey, v10);
   //   _mm_storeu_si128(key.mRoundKey + 1, _mm_aesimc_si128(v9));
   //   _mm_storeu_si128(key.mRoundKey + 2, _mm_aesimc_si128(v8));
   //   _mm_storeu_si128(key.mRoundKey + 3, _mm_aesimc_si128(v7));
   //   _mm_storeu_si128(key.mRoundKey + 4, _mm_aesimc_si128(v6));
   //   _mm_storeu_si128(key.mRoundKey + 5, _mm_aesimc_si128(v5));
   //   _mm_storeu_si128(key.mRoundKey + 6, _mm_aesimc_si128(v4));
   //   _mm_storeu_si128(key.mRoundKey + 7, _mm_aesimc_si128(v3));
   //   _mm_storeu_si128(key.mRoundKey + 8, _mm_aesimc_si128(v2));
   //   _mm_storeu_si128(key.mRoundKey + 9, _mm_aesimc_si128(v1));
   //   _mm_storeu_si128(key.mRoundKey + 10, v0);
   //}

   //void AES128::EcbDecBlock(const Key& key, const block& src, block& dest)
   //{

   //   dest = _mm_xor_si128(src, key.mRoundKey[0]);
   //   dest = _mm_aesdec_si128(dest, key.mRoundKey[1]);
   //   dest = _mm_aesdec_si128(dest, key.mRoundKey[2]);
   //   dest = _mm_aesdec_si128(dest, key.mRoundKey[3]);
   //   dest = _mm_aesdec_si128(dest, key.mRoundKey[4]);
   //   dest = _mm_aesdec_si128(dest, key.mRoundKey[5]);
   //   dest = _mm_aesdec_si128(dest, key.mRoundKey[6]);
   //   dest = _mm_aesdec_si128(dest, key.mRoundKey[7]);
   //   dest = _mm_aesdec_si128(dest, key.mRoundKey[8]);
   //   dest = _mm_aesdec_si128(dest, key.mRoundKey[9]);
   //   dest = _mm_aesdeclast_si128(dest, key.mRoundKey[10]);

   //}

//#endif

}