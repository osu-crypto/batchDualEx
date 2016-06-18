#pragma once
#include "Common/Defines.h"
#include "Common/BitVector.h"
#include "Crypto/PRNG.h"
#include "Crypto/Commit.h"
#include "Network/Channel.h"
#include "OT/OTExtReceiver.h"
#include "OT/OTExtSender.h"
#include <vector>
#include "Common/Timer.h"
#include <array>
//#include "boost/multi_array.hpp"

//#define ASYNC_PSI

namespace libBDX
{


	class PsiSender
	{
	public:
		PsiSender() :mCommitedFuture(mCommitedProm.get_future()), mPSIValsComputedFuture(mPSIValsComputedProm.get_future()), mRemainingInputCommits(0) {}

		std::promise<void> mCommitedProm, mPSIValsComputedProm;
		std::shared_future<void> mCommitedFuture, mPSIValsComputedFuture;



		std::atomic<u32> mRemainingInputCommits, mRemainingPSIVals;
		std::vector<BitVector> mTheirPermute;
		u64 mWordSize;

		//PSISender(u64 wordSize) :mWordSize(wordSize) { assert(wordSize <= 128); }

		void init(u64 size, u64 wordSize, Channel& chl, I_OTExtSender& otSend, u64& otIdx, PRNG& prng);

		//boost::multi_array<block, 2> mPseVals;
		std::vector<std::vector<block>> mPseVals;



		I_OTExtSender* mOTSend;
		u64 mOTIdx;
		Timer timer;
		//const std::vector<block>* mInputs;

		void CommitRecv(Channel& chl, u64 idx);
		void CommitSend(block& inputs, Channel& chl, u64 idx);



		void open(Channel& chl, u64 idx);
		static u64 PsiOTCount(u64 inputSize, u64 wordSize);

	};

}
