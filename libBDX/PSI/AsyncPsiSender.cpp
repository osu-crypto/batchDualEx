#include "PSI/AsyncPsiSender.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"

namespace osuCrypto
{


#define PSI_DEBUG

	extern	block psiPRF(const block& b, u64 i);



	void AsyncPsiSender::init(u64 inputSize, u64 wordSize, Channel & chl, BDX_OTExtSender & otSend, u64& otIdx, PRNG& prng)
	{

		mWordSize = wordSize;
		mTheirPermute.resize(inputSize);
		mRemainingPSIVals = static_cast<u32>(inputSize);

		mRemainingInputCommits = static_cast<u32>(inputSize * 2);

		block ZiXorSum, Zi;
		std::unique_ptr<ByteStream> buff;

		u64 theirInputSize = inputSize;
		u64 myInputSize = inputSize;
		u64 otStartIdx = otIdx;
		u64 b;
		otIdx += PsiOTCount(inputSize, mWordSize);

		if (inputSize == 0)
			throw std::runtime_error("");
		//Lg::mMtx.lock();

		// for each of my inputs in the private set membership test (PSMT), permute the order that I
		// commitment to the j'th input's shares by mMyPermute[j]. And use the same permute order
		// for each of PSMT that we do. This is important because we will commit to our input by
		// sending (mMyPermute[j] ^ input[j]).
		mMyPermute.clear();
		mMyPermute.resize(myInputSize);
		for (u64 j = 0; j < myInputSize; ++j)
		{
			mMyPermute[j].reset(mWordSize);
			mMyPermute[j].randomize(prng);
			//std::cout << "send " << (u16)this << " perm " << mMyPermute[j] << std::endl;
		}

		//mShares.resize(std::array<u64, 4>{ {theirInputSize, myInputSize, mWordSize, 2} });
		mShares.resize(theirInputSize);
		for (auto& r : mShares)
		{
			r.resize(myInputSize);
			for (auto& t : r)t.resize(mWordSize);
		}

		mOpenBuff.resize(theirInputSize);
		// for each of their inputs, do a PSMT with my set
		for (u64 i = 0; i < theirInputSize; ++i)
		{
			mOpenBuff[i].resize(myInputSize);

			for (u64 j = 0; j < myInputSize; ++j)
			{

				buff.reset(new ByteStream(sizeof(Commit) * mWordSize * 2));
                auto buffIter = (Commit*)buff->data();

				// for each of the inputs in this PSMT, encode them using the same ot msgs, and make
				// them unique using the prf and my input idx
				u64 oti = otStartIdx + i * mWordSize;

				// clear the blind so that it sums to zero...
				ZiXorSum = ZeroBlock;

				// commit to each share of this encoding, and permute them by mMyPermute
				for (b = 0; b < mWordSize - 1; ++b, ++oti)
				{
					// compute the next blinding term
					Zi = ZeroBlock;// prng.get<block>();
					ZiXorSum = ZiXorSum ^ Zi;

					// permute the b'th bit encoding of my j'th input by mMyPermute[j][b]. use the
					// same permute for each of the PSMTs
					u8 c = mMyPermute[j][b];

					// make the share the PRF of the OT msg and our input idx, then xor it with the
					// blinding value Zi.
					mShares[i][j][b][0] = psiPRF(otSend.GetMessage(oti, c), j) ^ Zi;
					mShares[i][j][b][1] = psiPRF(otSend.GetMessage(oti, c ^ 1), j) ^ Zi;

					//if (oti < PsiOTCount(myInputSize, mWordSize))
					//	std::cout << "  recv r" << i << " s" << j << " b" << b << " " << mShares[i][j][b][0] << " " << mShares[i][j][b][1] << std::endl;

					//std::cout << "send " << (u16)this << " "
						//<< otSend.GetMessage(oti, c) << " ("<< (u32)c <<") ,j -> " << mShares[i][j][b][0] << "     " 
						//<< otSend.GetMessage(oti, c ^ 1) << " (" << (u32)(c^1) << ") ,j -> "<< mShares[i][j][b][1]  << "  "  << oti << std::endl;

					// append the commitment of the shares to the buffer
					(*buffIter++) =(Commit(mShares[i][j][b][0]));
					(*buffIter++) =(Commit(mShares[i][j][b][1]));
				}               

				// do the same thing but set Zi to be ZiXorSum so that the Zi's sum to zero
				Zi = ZiXorSum;

				u8 c = mMyPermute[j][b];

				mShares[i][j][b][0] = psiPRF(otSend.GetMessage(oti, c), j) ^ Zi;
				mShares[i][j][b][1] = psiPRF(otSend.GetMessage(oti, c ^ 1), j) ^ Zi;

				//std::cout << "send " << (u16)this << " "
				//	<< otSend.GetMessage(oti, c) << " (" << (u32)c << ") ,j -> " << mShares[i][j][b][0] << "     "
				//	<< otSend.GetMessage(oti, c ^ 1) << " (" << (u32)(c ^ 1) << ") ,j -> " << mShares[i][j][b][1] << "  " << oti << std::endl;


                (*buffIter++) = (Commit(mShares[i][j][b][0]));
                (*buffIter++) = (Commit(mShares[i][j][b][1]));

				chl.asyncSend(std::move(buff));

				//++oti;

				// allocate a buffer used in the online phase to avoid the allocation then.
				mOpenBuff[i][j].reset(new ByteStream(sizeof(block) * mWordSize));

			}
		}
		//Lg::mMtx.unlock();


		//{
		//	ByteStream buf;
		//	buf.resize(PsiOTCount(inputSize, mWordSize) * sizeof(block) * 2);
		//	auto arr = buf.getArrayView<std::array<block, 2>>();

		//	for (u64 i = 0; i < arr.size(); i++)
		//	{
		//		arr[i][0] = otSend.GetMessage(i + otStartIdx, 0);
		//		arr[i][1] = otSend.GetMessage(i + otStartIdx, 1);
		//	}

		//	chl.asyncSendCopy(buf);
		//}

	}

	void AsyncPsiSender::AsyncCommitSend(block& inputBlk, Channel& chl, u64 i)
	{

		u64 theirInputSize = mShares.size();
		u64 myInputSize = mShares[0].size();


		BitVector input((u8*)&inputBlk, mWordSize);
		mMyPermute[i] ^= input;

		std::unique_ptr<BitVector>inputPermute(new BitVector(mMyPermute[i]));
		chl.asyncSend(std::move(inputPermute));

		//std::cout << "P" << (int)role << " cmp  mTheirPermute[" << j << "] = " << mTheirPermute[j] << std::endl;
		//Lg::mMtx.lock();
		//std::cout << "send " << (u16)this << " input " << i << "  " << input << "  correct " << mMyPermute[i]<< std::endl << std::endl;
		//Lg::mMtx.unlock();

		u64 rem = --mRemainingInputCommits;
		if (rem == 0)
			mCommitedProm.set_value();

	}

	void AsyncPsiSender::AsyncCommitRecv(Channel& chl, u64 i)
	{

		//for (u64 i = 0; i < theirInputSize; ++i)
		//{
		mTheirPermute[i].reset(mWordSize);
		chl.recv(mTheirPermute[i]);


		u64 rem = --mRemainingInputCommits;
		if (rem == 0)
			mCommitedProm.set_value();
		else// (mRemainingInputCommits != 0)
			mCommitedFuture.get();

		u64 myInputSize = mShares[0].size();

		//{
			//std::lock_guard<std::mutex> lock(Lg::mMtx);
			for (u64 j = 0; j < myInputSize; ++j)
			{
				//block tt = ZeroBlock;
				for (u64 b = 0; b < mWordSize; ++b)
				{

					u8 bit = mTheirPermute[i][b] ^ mMyPermute[j][b];
					//std::cout << "  send " << (u16)this << " r" << i << " s" << j << " b" << b << "  bit " << (int)bit << "=" << (int)mMyPermute[j][b] << "+" << (int)mTheirPermute[i][b] << "  " << mShares[i][j][b][bit] << std::endl;
					//tt = tt ^ mShares[i][j][b][bit];

					((block*)mOpenBuff[i][j]->data())[b] = (mShares[i][j][b][bit]);
				}

				//std::cout << "send " << (u16)this << " sum r " << i << " s " << j<< "  " << tt << std::endl << std::endl;
			}

		//}
	}




	u64 AsyncPsiSender::PsiOTCount(u64 inputSize, u64 wordSize)
	{
		return inputSize * inputSize * wordSize;
	}

	void AsyncPsiSender::open(Channel & chl, u64 idx)
	{
		u64 myInputSize = mShares[0].size();

		for (u64 j = 0; j < myInputSize; ++j)
		{
			chl.asyncSend(std::move(mOpenBuff[idx][j]));
		}
	}
}