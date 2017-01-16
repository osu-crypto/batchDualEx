#include "OTExtSender.h"

//#include "OT/BaseOT.h"
//#include "OT/Tools.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/ByteStream.h"
#include "cryptoTools/Crypto/Commit.h"
#include "libOTe/Tools/Tools.h"

#ifdef GetMessage
#undef GetMessage
#endif

namespace osuCrypto
{
	//#define OTEXT_DEBUG

	using namespace std;


	const block& BDX_OTExtSender::GetMessage(u64 idx, const u8 choice) const
	{
		return  mMessages[choice][idx];
	}

//
//	void BDX_OTExtSender::Extend(
//		std::array<block, 128>& baseMessages,
//		BitVector& baseChoiceBits,
//		u64 numOTExt,
//		PRNG& prng,
//		Channel& chl,
//		std::atomic<u64>& atomicDoneIdx)
//	{
//
//		if (numOTExt == 0) return;
//
//		// round up
//		numOTExt = ((numOTExt + 127) / 128) * 128;
//
//		// add k to account for the extra 128 OTs used for the correlation check
//		numOTExt += 128;
//
//		// the raw container that will be reused.
//		//BitVector buf0(numOTExt);
//
//		// column vector form of q, the sender masking matrix
//		std::array<block, 128> q;
//
//		// set up the row form of the senders and receivers outputs
//		mMessages[0].resize(numOTExt + 1);
//		mMessages[1].resize(numOTExt + 1);
//
//
//		ByteStream buff;
//		std::array<PRNG, 128> gens;
//
//
//		for (int i = 0; i < 128; i++)
//		{
//			gens[i].SetSeed(baseMessages[i]);
//		}
//
//
//		block seed;
//		// not sure if its secure to do the commit here. Need to check the sec proof or commit
//		// this after sending/receiving stuff.
//		random_seed_commit(ByteArray(seed), chl, SEED_SIZE, prng.get<block>());
//		PRNG commonPrng(seed);
//
//		block  chii, qi, qi2;
//		block q2 = ZeroBlock;
//		block q1 = ZeroBlock;
//		block delta = baseChoiceBits.ToBlock();
//		//auto& delta = baseOTs.receiver_inputs;
//		SHA1 sha;
//
//#ifdef OTEXT_DEBUG
//		std::cout << "sender delta " << delta << std::endl;
//		buff.append(delta);
//		chl.asyncSendCopy(buff);
//#endif
//
//
//		//assert(doneIdx == 0);
//		u64 doneIdx = 0;
//		u64 numBlocks = numOTExt / 128;
//		for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
//		{
//
//			chl.recv(buff);
//			assert(buff.size() == sizeof(block) * 128);
//
//			// u = t0 + t1 + x 
//			block* u = (block*)buff.data();
//
//			for (int colIdx = 0; colIdx < 128; colIdx++)
//			{
//				// a column vector sent by the receiver that hold the correction mask.
//				q[colIdx] = gens[colIdx].get<block>();
//
//				if (baseChoiceBits[colIdx])
//				{
//					// now q[i] = t0[i] + Delta[i] * x
//					q[colIdx] = q[colIdx] ^ u[colIdx];
//				}
//			}
//
//			eklundh_transpose128(q);
//
//#ifdef OTEXT_DEBUG
//			buff.setp(0);
//			buff.append((u8*)&q, sizeof(q));
//			chl.asyncSendCopy(buff);
//#endif
//
//			for (int blkRowIdx = 0; blkRowIdx < 128; ++blkRowIdx, ++doneIdx)
//			{
//				auto& msg0 = q[blkRowIdx];
//				auto msg1 = q[blkRowIdx] ^ delta;
//
//				// hash the message without delta
//				sha.Reset();
//				sha.Update((u8*)&msg0, sizeof(block));
//				sha.Final((u8*)&mMessages[0][doneIdx]);
//
//				// hash the message with delta
//				sha.Reset();
//				sha.Update((u8*)&msg1, sizeof(block));
//				sha.Final((u8*)&mMessages[1][doneIdx]);
//
//
//				chii = commonPrng.get<block>();
//
//				mul128(msg0, chii, &qi, &qi2);
//				q1 = q1  ^ qi;
//				q2 = q2 ^ qi2;
//			}
//
//			atomicDoneIdx = doneIdx;
//		}
//
//		block t1, t2;
//		std::vector<char> data(sizeof(block) * 3);
//
//		chl.recv(data.data(), data.size());
//
//		block& received_x = ((block*)data.data())[0];
//		block& received_t = ((block*)data.data())[1];
//		block& received_t2 = ((block*)data.data())[2];
//
//		// check t = x * Delta + q 
//		mul128(received_x, delta, &t1, &t2);
//		t1 = t1 ^ q1;
//		t2 = t2 ^ q2;
//
//		if (eq(t1, received_t) && eq(t2, received_t2))
//		{
//			//std::cout << "\tCheck passed\n";
//		}
//		else
//		{
//			std::cout << "OT Ext Failed Correlation check failed" << std::endl;
//			std::cout << "rec t = " << __m128i_toString<u8>(received_t) << std::endl;
//			std::cout << "tmp1  = " << __m128i_toString<u8>(t1) << std::endl;
//			std::cout << "q  = " << __m128i_toString<u8>(q1) << std::endl;
//			throw std::runtime_error("Exit");;
//		}
//
//		static_assert(128 == 128, "expecting 128");
//		mMessages[0].resize(numOTExt - 129);
//		mMessages[1].resize(numOTExt - 129);
//	}

	void BDX_OTExtSender::Extend(
        const ArrayView<block>& baseMessages,
        const BitVector& baseChoiceBits,
		u64 otCount,
		PRNG& prng,
		Channel& chl,
		std::atomic<u64>& atomicDoneIdx)
	{
		if (otCount == 0) return;

	
		// round up and add 128 for correlation check
		u64 numOTExt = ((otCount + 127) / 128) * 128 + 128;


		SHA1 sha;
		u8 hashBuff[SHA1::HashSize];


		std::array<block, 128> q;

		std::array<PRNG, 128> gens;
		for (int i = 0; i < 128; i++)
		{
			gens[i].SetSeed(baseMessages[i]);
		}


		ByteStream buff;
#ifdef OTEXT_DEBUG
		std::cout << "sender delta " << delta << std::endl;
		buff.append(delta);
		chl.AsyncSendCopy(buff);
#endif
#ifdef AES_HASH
		std::array<block, 2> enc;
#endif // AES_HASH
		std::array<block, 2> msg;

		mMessages[0].resize(otCount);
		mMessages[1].resize(otCount);

		Commit theirSeedComm;
		chl.recv(theirSeedComm.data(), theirSeedComm.size());
        block delta = baseChoiceBits.getArrayView<block>()[0];// .ToBlock();

		//block delta = *(block*)mBaseChoiceBits.data();

		std::vector<block> correlatedMessages(numOTExt);
		auto correlatedMessagesIter = correlatedMessages.begin();;
		//Lg::mMtx.lock();
		// add one for the extra 128 OTs used for the correlation check
		u64 numBlocks = numOTExt / 128, dIdx(0);
		for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
		{

			chl.recv(buff);
			assert(buff.size() == sizeof(block) * 128);

			// u = t0 + t1 + x 
			auto u = buff.getArrayView<block>();

			for (int colIdx = 0; colIdx < 128; colIdx++)
			{
				// a column vector sent by the receiver that hold the correction mask.
				q[colIdx] = gens[colIdx].get<block>();

				if (baseChoiceBits[colIdx])
				{
					// now q[i] = t0[i] + Delta[i] * x
					q[colIdx] = q[colIdx] ^ u[colIdx];
				}
			}

			//eklundh_transpose128(q);
            sse_transpose128(q);

#ifdef OTEXT_DEBUG
			buff.setp(0);
			buff.append((u8*)&q, sizeof(q));
			chl.AsyncSendCopy(buff);
#endif

			u32 blkRowIdx = 0;
			u32 stopIdx = (u32)std::min(u64(128), otCount - atomicDoneIdx.load(std::memory_order::memory_order_relaxed));
			for (blkRowIdx = 0; blkRowIdx < stopIdx; ++blkRowIdx, ++dIdx)
			{
				*correlatedMessagesIter++ = (q[blkRowIdx]);

				msg[0] = correlatedMessages[dIdx];
				msg[1] = msg[0] ^ delta;

#ifdef AES_HASH
				mAesFixedKey.ecbEncTwoBlocks(msg.data(), enc.data());
				messages[0][dIdx] = enc[0] ^ msg[0];
				messages[1][dIdx] = enc[1] ^ msg[1];
#else
				// hash the message without delta
				sha.Reset();
				sha.Update((u8*)&msg[0], sizeof(block));
				sha.Final(hashBuff);
				mMessages[0][dIdx] = *(block*)hashBuff;

				// hash the message with delta
				sha.Reset();
				sha.Update((u8*)&msg[1], sizeof(block));
				sha.Final(hashBuff);
				mMessages[1][dIdx] = *(block*)hashBuff;

				//std::cout << "s " << dIdx << "  " << mMessages[0][dIdx] << "  " << mMessages[1][dIdx] << std::endl;

#endif // AES_HASH
			}
			
			atomicDoneIdx = dIdx;

			for (; blkRowIdx < 128; ++blkRowIdx)
			{
				*correlatedMessagesIter++ = (q[blkRowIdx]);
			}
		}

		//Lg::mMtx.unlock();

		block seed = prng.get<block>();
		chl.asyncSend(&seed, sizeof(block));


		block theirSeed;
		chl.recv(&theirSeed, sizeof(block));

		if (Commit(theirSeed) != theirSeedComm)
			throw std::runtime_error("bad commit " LOCATION);

		//std::cout << "seed " << seed << "  " << theirSeed << std::endl;
		//random_seed_commit(ByteArray(seed), chl, SEED_SIZE, prng.get<block>());
		PRNG commonPrng(seed ^ theirSeed);

		//std::cout << commonPrng.mIndexArray[0]<< " " << commonPrng.mBuffer[0] << " " << ZeroBlock << std::endl;

		block  chii, qi, qi2;
		block q2 = ZeroBlock;
		block q1 = ZeroBlock;

		//std::cout << "sender size " << correlatedMessages.size() << std::endl;
		//Lg::mMtx.lock();
		for (u64 i = 0; i < correlatedMessages.size(); ++i)
		{
			chii = commonPrng.get<block>();

			//std::cout << "s " << i << "  " << correlatedMessages[i] << "  " << (correlatedMessages[i] ^ delta) << std::endl;

			mul128(correlatedMessages[i], chii, qi, qi2);
			q1 = q1  ^ qi;
			q2 = q2 ^ qi2;
		}
		//Lg::mMtx.unlock();

		std::vector<char> data(sizeof(block) * 3);

		chl.recv(data.data(), data.size());

		block& received_x = ((block*)data.data())[0];
		block& received_t = ((block*)data.data())[1];
		block& received_t2 = ((block*)data.data())[2];

		block t1, t2;

		//std::cout << "delta  = " << delta << std::endl;
		//std::cout << "rec x  = " << received_x << std::endl << std::endl;

		// check t = x * Delta + q 
		mul128(received_x, delta, t1, t2);

		//std::cout << "tmp1   = " << t1 << std::endl << std::endl;
		//std::cout << "q1     = " << q1 << std::endl << std::endl;


		auto t1p = t1 ^ q1;
		auto t2p = t2 ^ q2;

		//std::cout << "tmp1 p = " << t1p << std::endl << std::endl;


		if (eq(t1p, received_t) && eq(t2p, received_t2))
		{
			//std::cout << "\t--------Check passed---------\n";
			////std::cout << "OT Ext Failed Correlation check failed" << std::endl;
			//std::cout << "delta  = " << delta << std::endl;
			//std::cout << "rec x  = " << received_x << std::endl << std::endl;
			//std::cout << "rec t  = " << received_t << std::endl;
			//std::cout << "rec t2 = " << received_t2 << std::endl;
			//std::cout << "tmp1 p = " << t1p << std::endl;
			//std::cout << "tmp1   = " << t1 << std::endl;
			//std::cout << "q      = " << q1 << std::endl;
		}
		else
		{
			std::cout << "OT Ext Failed Correlation check failed" << std::endl <<std::endl;

			std::cout << " t1p != received_t || t2p != received_t2" << std::endl;
			std::cout <<  t1p << "  "<< received_t <<"  || " << t2p << " "<< received_t2 << std::endl << std::endl;

			std::cout << "delta  = " << delta << std::endl;
			std::cout << "rec x  = " << received_x << std::endl << std::endl;
			std::cout << "rec t  = " << received_t << std::endl;
			//std::cout << "rec t2 = " << received_t2 << std::endl;
			std::cout << "tmp1 p = " << t1p << std::endl;
			//std::cout << "tmp1   = " << t1 << std::endl;
			//std::cout << "q      = " << q1 << std::endl;
			throw std::runtime_error("Exit");;
		}

		static_assert(128 == 128, "expecting 128");
	}

}
