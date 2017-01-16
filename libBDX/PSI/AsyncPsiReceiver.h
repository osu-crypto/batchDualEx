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
#include "cryptoTools/Common/ArrayView.h"
//#define ASYNC_PSI

namespace osuCrypto
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


        BDX_OTExtReceiver* motRecv;
		u64 mOTIdx;

		void init(u64 inputSize, u64 wordSize, Channel& chl, BDX_OTExtReceiver& otRecv, u64& otIdx);

		void CommitSend(const block& inputs, Channel& chl, u64 idx);
		void CommitRecv(Channel& chl, u64 idx);

		bool open(Channel & chl, u64 idx, Role role);

		static u64 PsiOTCount(u64 inputSize, u64 wordSize);


	};
}