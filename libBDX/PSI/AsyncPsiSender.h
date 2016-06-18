#pragma once
#include "Common/Defines.h"
#include "Network/Channel.h"
#include "Common/BitVector.h"
#include "Crypto/PRNG.h"
#include "Crypto/Commit.h"
#include "OT/OTExtReceiver.h"
#include "OT/OTExtSender.h"
#include <vector>
#include <array>
//#include "boost/multi_array.hpp"


namespace libBDX
{


	class AsyncPsiSender
	{
	public:
		AsyncPsiSender() :mCommitedFuture(mCommitedProm.get_future()), mPSIValsComputedFuture(mPSIValsComputedProm.get_future()), mRemainingInputCommits(0) {}

		std::promise<void> mCommitedProm, mPSIValsComputedProm;
		std::shared_future<void> mCommitedFuture, mPSIValsComputedFuture;



		std::atomic<u32> mRemainingInputCommits, mRemainingPSIVals;
		std::vector<BitVector> mTheirPermute;
		u64 mWordSize;

		//PSISender(u64 wordSize) :mWordSize(wordSize) { assert(wordSize <= 128); }

		void init(u64 size, u64 wordSize, Channel& chl, I_OTExtSender& otSend, u64& otIdx, PRNG& prng);

		std::vector<BitVector> mMyPermute;
		std::vector<std::vector<std::vector<std::array<block, 2>>>> mShares;
		std::vector<std::vector<std::unique_ptr<ByteStream>>> mOpenBuff;

		void AsyncCommitSend(block& inputs, Channel& chl, u64 idx);
		void AsyncCommitRecv(Channel& chl, u64 idx);


		static u64 PsiOTCount(u64 inputSize, u64 wordSize);

		void open(Channel& chl, u64 idx);

	};

}