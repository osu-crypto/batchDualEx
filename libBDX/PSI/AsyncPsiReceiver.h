#pragma once
#include "Common/Defines.h"
#include "Network/Channel.h"
#include "Common/BitVector.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"
#include "Crypto/Commit.h"
#include "OT/OTExtReceiver.h"
#include "OT/OTExtSender.h"
#include <vector>
#include <array>
#include "Common/ArrayView.h"
//#define ASYNC_PSI

namespace libBDX
{



	class AsyncPsiReceiver
	{
	public:
		std::vector<BitVector> mMyPermute;
		u64 mWordSize;
		AsyncPsiReceiver() :mCommitedFuture(mCommitedProm.get_future()) {}

		std::promise<void> mCommitedProm;
		std::shared_future<void> mCommitedFuture;
		std::atomic<u32> mRemainingInputCommits;



		//boost::multi_array<Commit, 4> mCommits;
		std::vector<std::vector<std::vector<std::array<Commit, 2>>>> mCommits;
		std::vector<BitVector> mTheirPermute;


		I_OTExtReceiver* motRecv;
		u64 mOTIdx;

		void init(u64 inputSize, u64 wordSize, Channel& chl, I_OTExtReceiver& otRecv, u64& otIdx);

		void CommitSend(const block& inputs, Channel& chl, u64 idx);
		void CommitRecv(Channel& chl, u64 idx);

		bool open(Channel & chl, u64 idx, Role role);

		static u64 PsiOTCount(u64 inputSize, u64 wordSize);


	};
}