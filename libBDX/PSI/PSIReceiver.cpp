#include "PSI/PSIReceiver.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Crypto/AES.h"

namespace osuCrypto
{

#ifdef GetMessage
#undef GetMessage
#endif

	block psiPRF(const block& b, u64 i)
	{
		//TODO("REMOVE THIS!!");
		//return b;





		block ret, tweak = _mm_set1_epi64x(i), enc;

		ret = b ^ tweak;
        mAesFixedKey.ecbEncBlock(ret, enc);

		ret = ret ^ enc; // H( a0 ) 

		return ret;
	}


	void PsiReceiver::init(u64 inputSize, u64 wordSize, Channel & chl, BDX_OTExtReceiver & otRecv, u64& otStartIdx)
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
				//std::cout << "r m " << motRecv->GetMessage(otIdx) << " otIdx " << otIdx << " " << (u32)otRecv.mChoiceBits[otIdx] << "  " << (u32) mMyPermute[i][b]<< std::endl << std::endl;
				mask = mask  ^ motRecv->GetMessage(otIdx);
			}

			for (u64 j = 0; j < theirInputSize; ++j)
			{
				//mMyPSIValues[i][j] = ZeroBlock;
				//std::lock_guard<std::mutex> lock(Lg::mMtx);
				//std::cout << "r=" << i << " s=" << j << std::endl;


				mMyPSIValues[i][j] = psiPRF(mask, j);

				//std::cout << "psiPRF(sum, "<< j << ") " << mMyPSIValues[i][j] << std::endl;

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
		//std::cout << "recv have [" << idx << "] " << mMyPermute[idx] << std::endl;
		//std::cout << "recv input[" << idx << "] " << input << std::endl;

		mMyPermute[idx] ^= input;

		//std::cout << "recv permu[" << idx << "] " << mMyPermute[idx] << std::endl;
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
			//std::cout << "P"<< (int)role << " cmp r=" << idx << " s=" << j << " my " << mMyPSIValues[idx][j] << " thr "  << theirPse[j] << std::endl;

			//if (neq(psiPRF(*theirPse, idx), mCommits[j][idx]))
			if (Commit(theirPse[j]) != mCommits[j][idx])
			{
				//std::lock_guard<std::mutex> lock(Lg::mMtx);

				//std::cout 
				//	<< "P" << (int)role << " cmp r=" << idx << " s=" << j << "  " << mMyPSIValues[idx][j] << "  " << theirPse[j] 
				//	<< " ( " << Commit(theirPse[j]) << " " << mCommits[idx][j] << " )" << std::endl;

				throw std::runtime_error(LOCATION);
			}

			if (eq(mMyPSIValues[idx][j], theirPse[j]))
			{
				if (idx == 0) timer.setTimePoint("OpenEnd");

				return true;
				//output[j] = 1;
				//std::cout << "match " << idx  << "  (" << j << ")"<< std::endl;
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
