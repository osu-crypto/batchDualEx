#include "OTExtReceiver.h"
#include "OT/Tools.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Crypto/Commit.h"
#include "libOTe/Tools/Tools.h"
using namespace std;

namespace osuCrypto
{
	//#define OTEXT_DEBUG

		//BDX_OTExtReceiver::BDX_OTExtReceiver(Channel& channel)
		//	:mChannel(channel)
		//{
		//}

		//BDX_OTExtReceiver::~BDX_OTExtReceiver()
		//{
		//}

	//	void BDX_OTExtReceiver::Init(u64 numOTExt, PRNG& prng, std::atomic<u64>& doneIdx)
	//	{
	//		BaseOT baseOTs(0, mChannel, Sender);
	//		doneIdx = 0;
	//
	//		baseOTs.exec_base(prng);
	//#ifdef OTEXT_DEBUG
	//		baseOTs.check();
	//		DebugCheck0(baseOTs);
	//#endif
	//
	//		
	//
	//		Extend(baseOTs.sender_inputs, numBlocks, prng, doneIdx);
	//
	//
	//	}
	//
	//
#ifdef GetMessage
#undef GetMessage
#endif

	const block& BDX_OTExtReceiver::GetMessage(u64 i) const
	{
		return mMessages[i];
	}

//	void BDX_OTExtReceiver::Extend(
//		std::array< std::array<block, 2>, 128>& baseOTs,
//		u64 otCount,
//		PRNG& prng,
//		Channel& chl,
//		std::atomic<u64>& atomicDoneIdx)
//	{
//		if (otCount == 0) return;
//
//		// round up
//		u64 numOTExt = ((otCount + 127) / 128) * 128;
//
//		// add k to account for the extra 128 OTs used for the correlation check
//		numOTExt += 128;
//
//		// set up the row form of the receivers outputs. +1 for the sha hash size spill over...
//		mMessages = vector<block>(numOTExt + 1);
//
//		// resize to account for extra 128 OTs that are used for the correlation check
//		mChoiceBits.resize(numOTExt);
//
//		// use random choice bits
//		mChoiceBits.randomize(prng);
//
//		u64 numBlocks = numOTExt / 128;
//		// column vector form of t0, the receivers primary masking matrix
//		std::array<block, 128> t0;
//		std::array<std::array<PRNG, 2>, 128> gens;
//		for (int i = 0; i < 128; i++)
//		{
//			gens[i][0].SetSeed(baseOTs[i][0]);
//			gens[i][1].SetSeed(baseOTs[i][1]);
//		}
//
//		SHA1 sha;
//
//		PRNG G;
//		block seed;
//		random_seed_commit(ByteArray(seed), chl, SEED_SIZE, prng.get<block>());
//		G.SetSeed(seed);
//
//
//		std::unique_ptr<ByteStream> data(new ByteStream());
//		data->resize(3 * sizeof(block));
//		block& x = ((block*)data->data())[0];
//		block& t = ((block*)data->data())[1];
//		block& t2 = ((block*)data->data())[2];
//
//		x = t = t2 = ZeroBlock;
//		block chij, ti, ti2;
//
//		block* choiceBlocks = (block*)mChoiceBits.data();
//		//auto waitIter = waits.begin();
//
//#ifdef OTEXT_DEBUG
//		ByteStream debugBuff;
//		chl.recv(debugBuff);
//		block debugDelta; debugBuff.consume(debugDelta);
//
//		Lg::out << "delta" << Lg::endl << debugDelta << Lg::endl;
//#endif 
//		u64 doneIdx = 0;
//		for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
//		{
//			std::unique_ptr<ByteStream> buff(new ByteStream(128 * sizeof(block)));
//			buff->setp(128 * sizeof(block));
//
//			block* u = (block*)buff->data();
//
//			for (u64 colIdx = 0; colIdx < 128; colIdx++)
//			{
//				// use the base key material from the base OTs to extend the i'th column of t0 and t1	
//				t0[colIdx] = gens[colIdx][0].get<block>();
//				block t1i = gens[colIdx][1].get<block>();
//
//				u[colIdx] = t1i ^ (t0[colIdx] ^ choiceBlocks[blkIdx]);
//				//Lg::out << "Receiver sent u[" << colIdx << "]=" << u[colIdx] <<" = " << t1i <<" + " << t0[colIdx] << " + " << choiceBlocks[blkIdx] << Lg::endl;
//
//
//			}
//			chl.asyncSend(std::move(buff));
//
//			eklundh_transpose128(t0);
//
//#ifdef OTEXT_DEBUG 
//			chl.recv(debugBuff); assert(debugBuff.size() == sizeof(t0));
//			block* q = (block*)debugBuff.data();
//#endif
//
//			for (u64 blkRowIdx = 0; blkRowIdx < 128; ++blkRowIdx, ++doneIdx)
//			{
//#ifdef OTEXT_DEBUG
//				u8 choice = mChoiceBits[doneIdx];
//				block expected = choice ? (q[blkRowIdx] ^ debugDelta) : q[blkRowIdx];
//				Lg::out << (int)choice << " " << expected << Lg::endl;
//
//				if (t0[blkRowIdx] != expected)
//				{
//					Lg::out << "- " << t0[blkRowIdx] << Lg::endl;
//					throw std::runtime_error("");
//				}
//#endif
//
//				// hash it
//				sha.Reset();
//				sha.Update((u8*)&t0[blkRowIdx], sizeof(block));
//				sha.Final((u8*)&mMessages[doneIdx]);
//
//				// and check for correlation
//				chij = G.get<block>();
//				if (mChoiceBits[doneIdx]) x = x ^ chij;
//
//				// multiply over polynomial ring to avoid reduction
//				mul128(t0[blkRowIdx], chij, &ti, &ti2);
//
//				t = t ^ ti;
//				t2 = t2 ^ ti2;
//			}
//			atomicDoneIdx = doneIdx;
//
//		}
//
//
//		chl.asyncSend(std::move(data));
//
//		static_assert(128 == 128, "expecting 128");
//
//		mMessages.resize(otCount);
//		mChoiceBits.resize(otCount);
//	}
//
	void BDX_OTExtReceiver::Extend(
		std::array< std::array<block, 2>, 128>& baseOTs,
		u64 otCount,
		PRNG& prng,
		Channel& chl,
		std::atomic<u64>& atomicDoneIdx)
	{
		if (otCount == 0) return;

		// round up
		u64 numOTExt = ((otCount + 127) / 128) * 128;

		// add k to account for the extra 128 OTs used for the correlation check
		numOTExt += 128;

		// set up the row form of the receivers outputs.
		mMessages = vector<block>(otCount);

		// resize to account for extra 128 OTs that are used for the correlation check
		mChoiceBits.resize(numOTExt);

		// use random choice bits
		mChoiceBits.randomize(prng);

		// we are going to process OTs in blocks of 128 messages.
		u64 numBlocks = numOTExt / 128;

		// column vector form of t0, the receivers primary masking matrix
		// We only ever have 128 of them in memory at a time. Since we only
		// use it once and dont need to keep it around.
		std::array<block, 128> t0;


		SHA1 sha;
		u8 hashBuff[SHA1::HashSize];

		// commit to as seed which will be used to 
		block seed = prng.get<block>();
		Commit myComm(seed);
		chl.asyncSend(myComm.data(), myComm.size());

		// turn the choice vbitVector into an array of blocks. 
		
		auto choiceBlocks = mChoiceBits.getArrayView<block>();
		std::vector<block> correlatedMessages(mChoiceBits.size());

		std::array<std::array<PRNG, 2>, 128> gens;
		for (int i = 0; i < 128; i++)
		{
			gens[i][0].SetSeed(baseOTs[i][0]);
			gens[i][1].SetSeed(baseOTs[i][1]);
		}

#ifdef OTEXT_DEBUG
		ByteStream debugBuff;
		chl.recv(debugBuff);
		block debugDelta; debugBuff.consume(debugDelta);

		Lg::out << "delta" << Lg::endl << debugDelta << Lg::endl;
#endif 
#ifdef AES_HASH

		block enc;
#endif
		//Lg::mMtx.lock();
		u64 dIdx(0);
		for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
		{
			// this will store the next 128 rows of the matrix u
			std::unique_ptr<ByteStream> uBuff(new ByteStream(128 * sizeof(block)));
			uBuff->setp(128 * sizeof(block));

			// get an array of blocks that we will fill. 
			auto u = uBuff->getArrayView<block>();

			for (u64 colIdx = 0; colIdx < 128; colIdx++)
			{
				// use the base key material from the base OTs to 
				// extend the i'th column of t0 and t1	
				t0[colIdx] = gens[colIdx][0].get<block>();

				// This is t1[colIdx]
				block t1i = gens[colIdx][1].get<block>();

				// compute the next column of u (within this block) as this ha
				u[colIdx] = t1i ^ (t0[colIdx] ^ choiceBlocks[blkIdx]);

				//Lg::out << "Receiver sent u[" << colIdx << "]=" << u[colIdx] <<" = " << t1i <<" + " << t0[colIdx] << " + " << choiceBlocks[blkIdx] << Lg::endl;
			}

			// send over u buffer
			chl.asyncSend(std::move(uBuff));

			// transpose t0 in place
            sse_transpose128(t0);
			//eklundh_transpose128(t0);
            
#ifdef OTEXT_DEBUG 
			chl.recv(debugBuff); assert(debugBuff.size() == sizeof(t0));
			block* q = (block*)debugBuff.data();
#endif
			// now finalize and compute the correlation value for this block that we just processes
			u32 blkRowIdx;
			u32 stopIdx = (u32)std::min(u64(128), mMessages.size() - atomicDoneIdx.load(std::memory_order::memory_order_relaxed));
			for (blkRowIdx = 0; blkRowIdx < stopIdx; ++blkRowIdx, ++dIdx)
			{
#ifdef OTEXT_DEBUG
				u8 choice = mChoiceBits[dIdx];
				block expected = choice ? (q[blkRowIdx] ^ debugDelta) : q[blkRowIdx];
				Lg::out << (int)choice << " " << expected << Lg::endl;

				if (t0[blkRowIdx] != expected)
				{
					Lg::out << "- " << t0[blkRowIdx] << Lg::endl;
					throw std::runtime_error(LOCATION);
				}
#endif
				correlatedMessages[dIdx] = t0[blkRowIdx];

#ifdef AES_HASH
				mAesFixedKey.ecbEncBlock(correlatedMessages[dIdx], enc);
				mMessages[dIdx] = enc ^ correlatedMessages[dIdx];
#else
				// hash it
				sha.Reset();
				sha.Update((u8*)&correlatedMessages[dIdx], sizeof(block));
				sha.Final(hashBuff);
				mMessages[dIdx] = *(block*)hashBuff;
				//Lg::out << "r " <<dIdx << "  "<< mMessages[dIdx] << "  " << (u32)mChoiceBits[dIdx] << Lg::endl;
#endif
			}

			for (; blkRowIdx < 128; ++blkRowIdx, ++dIdx)
			{
				correlatedMessages[dIdx] = t0[blkRowIdx];
				//extraBlocks.push_back(t0[blkRowIdx]);

			}

			atomicDoneIdx = std::min((u64)dIdx, mMessages.size());

		}
		//Lg::mMtx.unlock();



		// do correlation check and hashing
		// For the malicious secure OTs, we need a random PRNG that is chosen random 
		// for both parties. So that is what this is. 
		PRNG commonPrng;
		//random_seed_commit(ByteArray(seed), chl, SEED_SIZE, prng.get<block>());
		block theirSeed;
		chl.recv(&theirSeed, sizeof(block));
		chl.asyncSendCopy(&seed, sizeof(block));
		commonPrng.SetSeed(seed ^ theirSeed);

		// this buffer will be sent to the other party to prove we used the 
		// same value of r in all of the column vectors...
		std::unique_ptr<ByteStream> correlationData(new ByteStream(3 * sizeof(block)));
		correlationData->setp(correlationData->capacity());
		block& x = correlationData->getArrayView<block>()[0];
		block& t = correlationData->getArrayView<block>()[1];
		block& t2 = correlationData->getArrayView<block>()[2];
		x = t = t2 = ZeroBlock;
		block chij, ti = ZeroBlock, ti2 = ZeroBlock;

		//Lg::out <<"recver size " << correlatedMessages.size() << Lg::endl;
		//Lg::mMtx.lock();

		for (u64 i = 0; i < correlatedMessages.size(); ++i)
		{
			// and check for correlation
			chij = commonPrng.get<block>();
			if (mChoiceBits[i]) x = x ^ chij;
			//Lg::out << "r " << i << "  " << correlatedMessages[i] /*<< "  " << chij */<< Lg::endl;

			// multiply over polynomial ring to avoid reduction
			mul128(correlatedMessages[i], chij, ti, ti2);

			t = t ^ ti;
			t2 = t2 ^ ti2;
		}

		//Lg::out << "r x = " << x << "  t " << t << "  t2 " << t2 << Lg::endl;

		//Lg::mMtx.unlock();

		chl.asyncSend(std::move(correlationData));

		mMessages.resize(otCount);
		mChoiceBits.resize(otCount);
		static_assert(128 == 128, "expecting 128");
	}


}
