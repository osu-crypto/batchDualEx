#include "PSI/AsyncPsiReceiver.h"
#include "Crypto/Commit.h"
#include "Common/Logger.h"
#include "Common/Defines.h"


namespace libBDX
{
	extern block PRF(const block& b, u64 i);


	u64 AsyncPsiReceiver::PsiOTCount(u64 inputSize, u64 wordSize)
	{
		return inputSize * inputSize * wordSize;
	}

	void AsyncPsiReceiver::init(u64 inputSize, u64 wordSize, Channel& chl, I_OTExtReceiver& otRecv, u64& otIdx)
		//void AsyncPsiReceiver::init(u64 inputSize, u64 wordSize, Channel & chl, ArrayView<block> otMessages, BitVector otChoices)
	{
		mWordSize = wordSize;
		//mOtMessages = otMessages;
		//mOtChoices = otChoices;

		//if (otMessages.size() != otChoices.size() || otMessages.size() != PsiOTCount(inputSize, wordSize))
		//	throw std::runtime_error("");
		motRecv = &otRecv;
		mOTIdx = otIdx;

		otIdx += PsiOTCount(inputSize, mWordSize);

		u64 myInputSize = inputSize;
		u64 theirInputSize = inputSize;

		mRemainingInputCommits = static_cast<u32>(inputSize * 2);

		//mCommits.resize(std::array<u64, 4>{ {myInputSize, theirInputSize, mWordSize, 2}});
		mCommits.resize(myInputSize);
		// performs a PSMT for each of my elements
		for (u64 i = 0; i < myInputSize; ++i)
		{
			mCommits[i].resize(theirInputSize);

			for (u64 j = 0; j < theirInputSize; ++j)
			{
				mCommits[i][j].resize(mWordSize);


				chl.recv(&mCommits[i][j][0][0], mWordSize * sizeof(Commit) * 2);
				//for (u64 b = 0; b < mWordSize; ++b)
				//{
				//	buff.consume(mCommits[i][j][b][0]);
				//	buff.consume(mCommits[i][j][b][1]);
				//}

				//if (buff.tellg() != buff.size())
				//	throw std::runtime_error("");
			}
		}


		//{
		//	std::vector<std::array<block, 2>> theirOts(PsiOTCount(inputSize, mWordSize));
		//	chl.recv(theirOts.data(), theirOts.size() * sizeof(std::array<block, 2>));

		//	for (u64 i = 0; i < theirOts.size(); ++i)
		//	{
		//		if (neq(otRecv.GetMessage(mOTIdx + i), theirOts[i][otRecv.mChoiceBits[mOTIdx + i]]))
		//			throw std::runtime_error("");
		//	}

		//}

		//Lg::out << "recv " + ToString(otStartIdx) << Lg::endl;


		mTheirPermute.resize(theirInputSize);
		for (u64 j = 0; j < theirInputSize; ++j)
		{
			mTheirPermute[j].reset(wordSize);
		}


		mMyPermute.resize(myInputSize);
		std::unique_ptr<BitVector> permute(new BitVector());
		permute->reserve(myInputSize * mWordSize);


		for (u64 i = 0, ii = mOTIdx; i < myInputSize; ++i, ii += mWordSize)
		{
			mMyPermute[i].copy(motRecv->mChoiceBits, ii, mWordSize);
		}

	}
	void AsyncPsiReceiver::CommitSend(const block& inputBlk, Channel& chl, u64 idx)
	{

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
		//	Lg::out << "recv "<<(u16)this << "   have [" << idx << "] " << mMyPermute[idx] << Lg::endl;
		//	Lg::out << "recv " << (u16)this << "   input[" << idx << "] " << input << Lg::endl;

		mMyPermute[idx] ^= input;

		//	Lg::out << "recv " << (u16)this << "   permu[" << idx << "] " << mMyPermute[idx] << Lg::endl;
		//}
		chl.asyncSend(mMyPermute[idx].data(), mMyPermute[idx].sizeBytes());
		//	}
		//}KO

		u64 rem = --mRemainingInputCommits;
		if (rem == 0)
			mCommitedProm.set_value();
	}

	void AsyncPsiReceiver::CommitRecv(Channel& chl, u64 idx)
	{
		u64 theirInputSize = mCommits[0].size();


		//BitVector temp(theirInputSize * mWordSize);
		chl.recv(mTheirPermute[idx]);

		//mTheirPermute.resize(theirInputSize);
		//for (u64 i = 0; i < theirInputSize; ++i)
		//{
		//	mTheirPermute[i].copy(temp, i * mWordSize, mWordSize);
		//}

		u64 rem = --mRemainingInputCommits;
		if (rem == 0)
			mCommitedProm.set_value();
	}


	//std::mutex mtx;
	bool AsyncPsiReceiver::open(Channel & chl, u64 idx, Role role)
	{

		//std::lock_guard<std::mutex>loc(mtx);

		auto& otRecv = *motRecv;
		ByteStream buff;
		block myPse, theirPse, *share;// , rand;
		u64 myInputSize = mCommits.size();
		u64 theirInputSize = mCommits[0].size();

		//output.reset(myInputSize);

		//u64 otStartIdx = otIdx;
		bool ret = false;

		if (mRemainingInputCommits != 0)
			mCommitedFuture.get();
		//for (u64 i = 0; i < myInputSize; ++i)
		//{
			//timer.setTimePoint("PSIrecv " + ToString(i));
		for (u64 j = 0; j < theirInputSize; ++j)
		{
			theirPse = myPse = ZeroBlock;
			u64 otIdx = mOTIdx + idx * mWordSize;

			chl.recv(buff);
			share = (block*)buff.data();

			//{
			//	std::lock_guard<std::mutex> lock(Lg::mMtx);

			if (buff.size() != sizeof(block) * mWordSize)
				throw std::runtime_error("");

			for (u64 b = 0; b < mWordSize; ++b, ++otIdx, ++share)
			{
				//buff.consume(share);
				//buff.consume(rand);

				theirPse = theirPse ^ *share;
				myPse = myPse ^ PRF(otRecv.GetMessage(otIdx), j);
				u8 bit = mMyPermute[idx][b] ^ mTheirPermute[j][b];

				//u64 c = otRecv.mChoiceBits[otIdx] ;

				//Lg::out << "  recv " << (u16)this << "   r" << idx << " s" << j << " b" << b << "  bit " << (int)bit << "=" << (int)mMyPermute[idx][b] << "+" << (int)mTheirPermute[j][b] 
				//	<< " " << otRecv.GetMessage(otIdx) << " ( " << c <<")"   << " , " << j << "  -> " << PRF(otRecv.GetMessage(otIdx), j) << "  otidx " << otIdx << Lg::endl;

				if (Commit(*share) != mCommits[idx][j][b][bit])
				{
					//std::lock_guard<std::mutex> lock(Lg::mMtx);

					//Lg::out << "P" << (int)role << " cmp r=" << idx << " s=" << j << "  " << mCommits[idx][j][b][bit] << "  " << Commit(*share) << Lg::endl;
					//Lg::out << "P" << (int)role << " cmp  mTheirPermute["<<j<<"] = " << mTheirPermute[j] << Lg::endl;
					throw invalid_commitment();
				}
			}
			//Lg::out << "recv  " << (u16)this << "  r " << idx << " s " << j << "  " << myPse << "  " << theirPse << Lg::endl << Lg::endl;

			if (eq(myPse, theirPse))
			{
				// My i'th element matches their j'th
				//Lg::out << "match i=" << idx << "  j=" << j << Lg::endl;
				//return true;
				//output[i] = 1;
				ret = true;
			}
			//}
		}
		//}
		return ret;

	}
}
