#include "PSI/PSIReceiver.h"
#include "Crypto/Commit.h"
#include "Common/Logger.h"
#include "Crypto/AES.h"

namespace libBDX
{

#ifdef GetMessage
#undef GetMessage
#endif

	block PRF(const block& b, u64 i)
	{
		//TODO("REMOVE THIS!!");
		//return b;





		block ret, tweak = _mm_set1_epi64x(i), enc;

		ret = b ^ tweak;
		AES128::EcbEncBlock(AES128::mAesFixedKey, ret, enc);

		ret = ret ^ enc; // H( a0 ) 

		return ret;
	}


	void PsiReceiver::init(u64 inputSize, u64 wordSize, Channel & chl, I_OTExtReceiver & otRecv, u64& otStartIdx)
	{
		mWordSize = wordSize;
		mOTIdx = otStartIdx;
		motRecv = &otRecv;
		u64 myInputSize = inputSize;
		u64 theirInputSize = inputSize;
		otStartIdx += wordSize * inputSize;

		timer.setTimePoint("initStart");
		mRemainingInputCommits = static_cast<u32>(inputSize);

		mCommits.resize(myInputSize);
		mMyPSIValues.resize(myInputSize);
		for (u64 i = 0; i < myInputSize; ++i) {
			mCommits[i].resize(theirInputSize);
			mMyPSIValues[i].resize(theirInputSize);

		}
		//mCommits.resize(std::array<u64, 2>{ {myInputSize, theirInputSize}});
		//mMyPSIValues.resize(std::array<u64, 2>{ {myInputSize, theirInputSize}});
		mMyPermute.resize(myInputSize);

		for (u64 i = 0, otIdx = mOTIdx; i < myInputSize; ++i)
		{
			mMyPermute[i].copy(otRecv.mChoiceBits, otIdx, mWordSize);

			block mask = ZeroBlock;
			for (u64 b = 0; b < mWordSize; ++b, ++otIdx)
			{
				//Lg::out << "r m " << motRecv->GetMessage(otIdx) << " otIdx " << otIdx << " " << (u32)otRecv.mChoiceBits[otIdx] << "  " << (u32) mMyPermute[i][b]<< Lg::endl << Lg::endl;
				mask = mask  ^ motRecv->GetMessage(otIdx);
			}

			for (u64 j = 0; j < theirInputSize; ++j)
			{
				//mMyPSIValues[i][j] = ZeroBlock;
				//std::lock_guard<std::mutex> lock(Lg::mMtx);
				//Lg::out << "r=" << i << " s=" << j << Lg::endl;


				mMyPSIValues[i][j] = PRF(mask, j);

				//Lg::out << "PRF(sum, "<< j << ") " << mMyPSIValues[i][j] << Lg::endl;

			}
		}
		timer.setTimePoint("initEnd");

	}
	void PsiReceiver::CommitSend(const block& inputBlk, Channel& chl, u64 idx)
	{
		if(idx == 0) timer.setTimePoint("CommSendStart");

		u64 myInputSize = mCommits.size();
		u64 theirInputSize = mCommits[0].size();

		//if (inputs.size() != myInputSize)
		//	throw std::runtime_error("");

		//if (idx == 0)
		//{
		//	for (u64 i = 0; i < myInputSize; ++i)
		//	{
		BitVector input((u8*)&inputBlk, mWordSize);


		//{
		//	std::lock_guard<std::mutex> lock(Lg::mMtx); 
		//Lg::out << "recv have [" << idx << "] " << mMyPermute[idx] << Lg::endl;
		//Lg::out << "recv input[" << idx << "] " << input << Lg::endl;

		mMyPermute[idx] ^= input;

		//Lg::out << "recv permu[" << idx << "] " << mMyPermute[idx] << Lg::endl;
		//}
		chl.asyncSend(mMyPermute[idx].data(), mMyPermute[idx].sizeBytes());
		//	}
		//}KO
		if(idx == 0) timer.setTimePoint("CommSendEnd");

	}

	void PsiReceiver::CommitRecv(Channel& chl, u64 idx)
	{
		u64 theirInputSize = mCommits[0].size();
		if(idx == 0) timer.setTimePoint("CommRecvStart");


		// recv their idx'th input encoded under each of the OT sets
		chl.recv(&mCommits[idx][0], theirInputSize * sizeof(Commit));



		u64 rem = --mRemainingInputCommits;
		if (rem == 0)
			mCommitedProm.set_value();
		if(idx == 0) timer.setTimePoint("CommRecvEnd");
	}


	//std::mutex mtx;
	bool PsiReceiver::open(Channel & chl, u64 idx, Role role)
	{
		if(idx == 0) timer.setTimePoint("OpenStart");


		if (mRemainingInputCommits != 0)
			mCommitedFuture.get();
		if (idx == 0) timer.setTimePoint("OpenStart'");

		ByteStream buff;
		//

		//for (u64 i = 0, k = 0; i < mCommits.size(); ++i)
		//{
		chl.recv(buff);
		if (idx == 0) timer.setTimePoint("OpenRecv");

		// All of the encodings which should match my idx'th input. I.e. their inputs {input_0, ..., input_n} encoded under 
		// the OTs set indexed by idx.
		auto theirPse = buff.getArrayView<block>();

		assert(buff.size() == mCommits.size() * sizeof(block));

		for (u64 j = 0; j < mCommits.size(); ++j)
		{
			//std::lock_guard<std::mutex> lock(Lg::mMtx);
			//Lg::out << "P"<< (int)role << " cmp r=" << idx << " s=" << j << " my " << mMyPSIValues[idx][j] << " thr "  << theirPse[j] << Lg::endl;

			//if (neq(PRF(*theirPse, idx), mCommits[j][idx]))
			if (Commit(theirPse[j]) != mCommits[j][idx])
			{
				//std::lock_guard<std::mutex> lock(Lg::mMtx);

				//Lg::out 
				//	<< "P" << (int)role << " cmp r=" << idx << " s=" << j << "  " << mMyPSIValues[idx][j] << "  " << theirPse[j] 
				//	<< " ( " << Commit(theirPse[j]) << " " << mCommits[idx][j] << " )" << Lg::endl;

				throw invalid_commitment();
			}

			if (eq(mMyPSIValues[idx][j], theirPse[j]))
			{
				if (idx == 0) timer.setTimePoint("OpenEnd");

				return true;
				//output[j] = 1;
				//Lg::out << "match " << idx  << "  (" << j << ")"<< Lg::endl;
			}
		}

		if(idx == 0) timer.setTimePoint("OpenEnd");
		return false;

	}
	u64 PsiReceiver::PsiOTCount(u64 inputSize, u64 wordSize)
	{
		return inputSize  * wordSize;
	}
}
