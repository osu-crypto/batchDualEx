#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "OT/OTExtReceiver.h"
#include <vector>
#include <array>
#include "PSI/PSISender.h"



namespace osuCrypto
{

	class PsiReceiver
	{
	public:
		std::vector<BitVector> mMyPermute;
		u64 mWordSize;
		PsiReceiver() :mCommitedFuture(mCommitedProm.get_future()) {}

		std::promise<void> mCommitedProm;
		std::shared_future<void> mCommitedFuture;
		std::atomic<u32> mRemainingInputCommits;



		//boost::multi_array<block,2> mCommits;
		//boost::multi_array<block,2> mMyPSIValues;

		std::vector<std::vector<Commit>> mCommits;
		std::vector<std::vector<block>> mMyPSIValues;

        BDX_OTExtReceiver* motRecv;
		u64 mOTIdx;
		Timer timer;
		 
		void init(u64 inputSize, u64 wordSize, Channel& chl, BDX_OTExtReceiver& otRecv, u64& otIdx);

		void CommitSend(const block& inputs, Channel& chl, u64 idx);
		void CommitRecv(Channel& chl, u64 idx);

		bool open(Channel & chl, u64 idx, Role role);

		static u64 PsiOTCount(u64 inputSize, u64 wordSize);


	};
}
