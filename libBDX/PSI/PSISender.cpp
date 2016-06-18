#include "PSI/PSISender.h"
#include "Crypto/Commit.h"
#include "Common/Logger.h"

namespace libBDX
{

#ifdef GetMessage
#undef GetMessage
#endif

//#define PSI_DEBUG

	extern	block PRF(const block& b, u64 i);

	void PsiSender::init(u64 inputSize, u64 wordSize, Channel & chl, I_OTExtSender & otSend, u64& otIdx, PRNG& prng)
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

		std::unique_ptr<ByteStream> buff;
		//for (u64 idx = 0; idx < theirInputSize; ++idx)
		//{
		BitVector input((u8*)&inputBlk, mWordSize);
#ifdef PSI_DEBUG 
		{
			Lg::out << "send input[" << idx << "] " << input << Lg::endl << Lg::endl;
		}
#endif
		u64 myInputSize = mTheirPermute.size();
		buff.reset(new ByteStream(sizeof(Commit) * myInputSize));

		for (u64 j = 0, otIdx = mOTIdx; j < myInputSize; ++j)
		{
#ifdef PSI_DEBUG
			Lg::out << "r=" << j << "  s=" << idx << Lg::endl;
#endif

			block mask = ZeroBlock;
			for (u64 b = 0; b < mWordSize; ++b, ++otIdx)
			{
				u8 bit = input[b] ^ mTheirPermute[j][b];
#ifdef PSI_DEBUG
				Lg::out 
					<< "s m " << mOTSend->GetMessage(otIdx, bit) << "   " 
				   	<< (u32)bit << "=" << (int)input[b] << "+" << (int)mTheirPermute[j][b] << " otIdx " << otIdx << Lg::endl 
					<< "    " << mOTSend->GetMessage(otIdx, 1 ^ bit) << Lg::endl;
#endif

				mask = mask ^ mOTSend->GetMessage(otIdx, bit);
			}
			
			TODO("fix false sharing. mPseVals[j][idx'!=idx] is written/read by other threads.");
			mPseVals[j][idx]= PRF(mask, idx);
			Commit comm(mPseVals[j][idx]);

#ifdef PSI_DEBUG

			Lg::out << "PRF(sum, "<<idx<<") " << mPseVals[j][idx]<< " , comm = " << comm << Lg::endl;
#endif

			buff->append(comm.data(), comm.size());
		}

		//chl.asyncSend(std::move(buff));
		chl.send(*buff);
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
