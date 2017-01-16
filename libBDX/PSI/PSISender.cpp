#include "PSI/PSISender.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"

namespace osuCrypto
{

#ifdef GetMessage
#undef GetMessage
#endif

//#define PSI_DEBUG

	extern	block psiPRF(const block& b, u64 i);

	void PsiSender::init(u64 inputSize, u64 wordSize, Channel & chl, BDX_OTExtSender & otSend, u64& otIdx, PRNG& prng)
	{

		mWordSize = wordSize;
		mTheirPermute.resize(inputSize);
		mRemainingPSIVals = static_cast<u32>(inputSize);

		mRemainingInputCommits = static_cast<u32>(inputSize);
		mOTSend = &otSend;
		mOTIdx = otIdx;
		otIdx += mWordSize * inputSize;
		//mPseVals.resize(inputSize);
		//for (auto& v : mPseVals)
		//	v.resize(inputSize);

		//mPseVals.resize(std::array<u64, 2>{ {inputSize, inputSize} });
		mPseVals.resize(inputSize);
		for (u64 i = 0; i < inputSize; ++i)
			mPseVals[i].resize(inputSize);
	}

	void PsiSender::CommitRecv(Channel& chl, u64 idx)
	{
		if(idx == 0) timer.setTimePoint("commRecvStart");
		//for (u64 idx = 0; idx < theirInputSize; ++idx)
		//{
		mTheirPermute[idx].reset(mWordSize);
		chl.recv(mTheirPermute[idx]);

		u64 rem = --mRemainingInputCommits;
		if (rem == 0)
			mCommitedProm.set_value();
		//else// (mRemainingInputCommits != 0)
		//	mCommitedFuture.get();
		if(idx == 0) timer.setTimePoint("commRecvEnd");
	}

	void PsiSender::CommitSend(block& inputBlk, Channel& chl, u64 idx)
	{
		if(idx == 0) timer.setTimePoint("commSendStart");
		//mInputs[idx] = &inputs;
		if (mRemainingInputCommits != 0)
			mCommitedFuture.get();
		if(idx == 0) timer.setTimePoint("commSendStart'");

		u64 myInputSize = mTheirPermute.size();
		std::unique_ptr<ByteStream> buff(new ByteStream(sizeof(Commit) * myInputSize));
		//for (u64 idx = 0; idx < theirInputSize; ++idx)
		//{
		BitVector input((u8*)&inputBlk, mWordSize);
#ifdef PSI_DEBUG 
		{
			std::cout << "send input[" << idx << "] " << input << std::endl << std::endl;
		}
#endif

		for (u64 j = 0, otIdx = mOTIdx; j < myInputSize; ++j)
		{
#ifdef PSI_DEBUG
			std::cout << "r=" << j << "  s=" << idx << std::endl;
#endif

			block mask = ZeroBlock;
			for (u64 b = 0; b < mWordSize; ++b, ++otIdx)
			{
				u8 bit = input[b] ^ mTheirPermute[j][b];
#ifdef PSI_DEBUG
				std::cout 
					<< "s m " << mOTSend->GetMessage(otIdx, bit) << "   " 
				   	<< (u32)bit << "=" << (int)input[b] << "+" << (int)mTheirPermute[j][b] << " otIdx " << otIdx << std::endl 
					<< "    " << mOTSend->GetMessage(otIdx, 1 ^ bit) << std::endl;
#endif

				mask = mask ^ mOTSend->GetMessage(otIdx, bit);
			}
			
			TODO("fix false sharing. mPseVals[j][idx'!=idx] is written/read by other threads.");
			mPseVals[j][idx]= psiPRF(mask, idx);

            ((Commit*)buff->data())[j] = Commit(mPseVals[j][idx]);

#ifdef PSI_DEBUG

			std::cout << "psiPRF(sum, "<<idx<<") " << mPseVals[j][idx]<< " , comm = " << comm << std::endl;
#endif

			//buff->append(comm.data(), comm.size());
		}

		chl.asyncSend(std::move(buff));
		//chl.send(*buff);
		//}

		u64 rem = --mRemainingPSIVals;
		if (rem == 0)
			mPSIValsComputedProm.set_value();
		
		if(idx == 0) timer.setTimePoint("commSendEnd");
	}


	void PsiSender::open(Channel & chl, u64 idx)
	{
		if(idx == 0) timer.setTimePoint("OpenStart");

		if (mRemainingPSIVals != 0)
			mPSIValsComputedFuture.get();

		u64 myInputSize = mPseVals[0].size();

		chl.asyncSend(&mPseVals[idx][0], sizeof(block) * myInputSize);
		if(idx == 0) timer.setTimePoint("OpenEnd");
	}
	u64 PsiSender::PsiOTCount(u64 inputSize, u64 wordSize)
	{
		return inputSize  * wordSize;
	}
}
