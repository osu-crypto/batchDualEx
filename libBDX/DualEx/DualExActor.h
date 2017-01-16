#pragma once
#include "Bucket.h"
#include "CircuitPackage.h"
#include "Circuit/Circuit.h"
#include "Circuit/HalfGtGarbledCircuit.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Common/Defines.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "Circuit/KProbeResistant.h"

//#define DUALEX_DEBUG
namespace osuCrypto
{

	class EvalBuff
	{};

	//mCircuit(cir),
	//	mRole(role),
	//	mNetMgr(netMgr),
	//	mNumExe(numExes),
	//	mBuckets(numExes),
	//	mBucketSize(bucketSize),
	//	mNumOpened(numOpened),
	//	mNumCircuits(numOpened + bucketSize * numExes),
	//	mPsiSecParam(psiSecParam),
	//	//mEvalIdx(0),
	//	mCnCCommitRecvDone(false)

	class DualExActor
	{
        
		std::vector<BDX_OTExtReceiver> mOTRecv;
		std::vector<BDX_OTExtSender> mOTSend;
		std::vector<Channel*> mRecvMainChls,mRecvSubChls, mSendSubChls;// , &mPsiChl;
		//std::vector<std::vector<Channel*>> mPSISendChls, mPSIRecvChls;
		//std::unique_ptr<std::mutex[]> mMtxs;
	public:

		const Circuit& mCircuit;
		KProbeMatrix mTheirKProbe, mMyKProbe;
		const Role mRole;
		Endpoint& mNetMgr;
		const u64 mNumExe, mBucketSize, mNumOpened,mNumCircuits, mPsiSecParam;
		std::atomic<bool> mCnCCommitRecvDone;
		std::vector<Bucket> mBuckets;
		//std::atomic<u64> mEvalIdx;

		//PRNG mPrng;

		 

		//ByteStream mTheirCnCCommit, mMyCnCCommit, mMyCnCOpen;


		DualExActor(
			const Circuit& cir,
			const Role role,
			const u64 numExes,
			const u64 bucketSize,
			const u64 numOpened,
			const u64 psiSecParam, 
			Endpoint & netMgr);

		~DualExActor()
		{

			close();

		}

		void close();

		void init(PRNG& prng, u64 numParallelInit, u64 numParallelEval, u64 numThreadsPerEval, Timer& timer);


		BitVector execute(u64 evalIdx, PRNG& prng, const BitVector& input, Timer& timer);


		void printTimes(std::string filename);
	private:
		
		std::vector<CommCircuitPackage> mTheirCircuits;
		std::vector<CircuitPackage> mMyCircuits;

		u64 mNumInitThreads;

		void initOnlinePhase(u64 numParallelEval, u64 numThreadsPerEval, PRNG& prng);

		void getSendOTs(block,u64, u64);
		void getRecvOTs(block, u64, u64);

		void initRecv(
			u64 initThrdIdx,
			block prngSeed,
			std::promise<void>& allCirReceived,
			std::array<std::vector<u64>, 2>& cutnChoose);

		void initSend(
			u64 initThrdIdx,
			block prngSeed,
			std::shared_future<void>& allCirReceived,
			std::shared_future<std::array<std::vector<u64>, 2>*>& cutnChooseSets);
		 
		void sendCircuitInputLoop(u64 circuitOffset, u64 circuitSkip, u64  bucketOffset, u64 bucketSkip, Channel& chl);


		std::vector<std::promise<void>> mCirRecvProm;
		std::vector<std::shared_future<void>> mCirRecvFutr;

		std::promise<void> mOnlineProm;
		std::shared_future<void> mOnlineFuture;

		std::promise<std::array<std::vector<u64>, 2>*> mOpenEvalSetsProm;
		std::shared_future<std::array<std::vector<u64>, 2>*> mTheirSetsFutr;

		std::array<std::vector<u64>, 2 > mMyCnCSets, mTheirCncSets;

		//boost::multi_array<block, 3>mLabels, mEncodedInputLabel;
		std::vector <std::vector <std::vector <block>>> mLabels;// , mEncodedInputLabel;
		std::vector<std::vector<block>> mOutLabels;
		void sendLoop(u64 idx, u64 numParallelEval, Channel& chl, PRNG& prng);
		void evalThreadLoop(u64 circuitOffset, u64 circuitSkip, u64  bucketOffset , u64 bucketSkip, PRNG& prng, Channel& chl);

		//std::atomic<bool> mSendOTDone, mRecvOTDone;
		//std::array<std::vector<std::unique_ptr<std::mutex[]>>,2> mPsiChannelLocks;

		std::unique_ptr<std::atomic<u64>[]> mOTSendDoneIdx, mOTRecvDoneIdx;

		std::thread mOTSendThrd, mOTRecvThrd;
		std::vector<std::thread> mEvalThreads, mSendMainThreads, mSendSubThreads;
		std::vector<block> mIndexArray;
		std::vector<Timer> mTimes;
		//PRNG mPrng, mSendPrng;
	};

}
