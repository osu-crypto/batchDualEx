#pragma once
#include <vector>
#include "cryptoTools/Common/BitVector.h"
#include "CircuitPackage.h"
#include "Circuit/KProbeResistant.h"
#include "PSI/PSIReceiver.h"
#include "PSI/PSISender.h"
#include "PSI/AsyncPsiReceiver.h"
#include "PSI/AsyncPsiSender.h"
#include <future>
#include "cryptoTools/Common/Timer.h"

//#define DUALEX_DEBUG
//#define ASYNC_PSI 
#define OFFLINE_KPROBE

namespace osuCrypto
{
	class Bucket
	{
	public:
		Bucket();
		~Bucket();


		void initRecv(
			const Circuit& cir,
			Channel& chl,
			KProbeMatrix& theirKProbe,
			u64 bucketSize,
			u64 psiSecParam,
			std::vector<u64>::iterator& cirIdxIter,
			std::vector<CommCircuitPackage>& circuits,
            BDX_OTExtSender  & otSend,
			PRNG& prng,
			u64& otIdx,
			Role role);


		void initSend(
			const Circuit& cir, 
			Channel& chl,
			u64 bucketSize,
			u64 psiSecParam,
			Role role,
			std::vector<CircuitPackage>& circuits, 
			std::vector<u64>::iterator& cirIdxIter,
			PRNG& prng,
			const KProbeMatrix& theirKProbe,
			const KProbeMatrix& myKprobe,
			BDX_OTExtReceiver & otRecv,
			u64& otIdx,
			const std::vector<block>& indexArray);
			

		void initKProbeInputRecv(
			const Circuit& cir,
			Channel& chl,
			KProbeMatrix& myKProbe,
			PRNG& prng,
			Role role);

		void initKProbeInputSend(const Circuit & cir, Channel & chl, KProbeMatrix & theirKProbe, PRNG & prng, Role role, const std::vector<block>& indexArray);


		void evaluate(
			const Circuit&  cir,
			const KProbeMatrix& theirKprobe,
			const KProbeMatrix& myKprobe,
			PRNG& prng, 
			Channel& chl,
			Role role,
			const BitVector& input,
			std::vector<std::vector<block>>& labels, 
			osuCrypto::Timer& timer);

		void sendCircuitInputs(
			const Circuit&  cir,
			const BitVector & input,
			Role role,
			Channel& chl,
			u64 circuitOffset,
			u64 circuitStep);

		void openTranslation(const Circuit& cir,  
			Channel& chl);


		void checkTranslation(const Circuit& cir,
			u64 cirIdx, 
			std::vector<block>& wireBuff,
			Role role);
		void Clear();

		std::vector<BitVector> mOutputs;

		BitVector mTheirInputCorrection;
		std::unique_ptr<BitVector> mInputCorrectionString;

		std::promise<const BitVector*> mInputPromise;
		std::shared_future<const BitVector*> mInputFuture;

		//std::promise<std::vector<block>*> mPsiInputsPromise;
		//std::future<std::vector<block>*> mPsiInputsFuture;

		std::promise<void> mTheirDeltasProm, mTheirInputCorrectionPromise, mMyCircuitsBucketedProm, mTranslationCheckDoneProm;// , mPSIInputCommittedProm;
		std::shared_future<void> mTheirDeltasFuture, mTheirInputCorrectionFuture, mMyCircuitsBucketedFuture, mTranslationCheckDoneFuture;// , mPSIInputCommittedFuture;

		std::vector<std::promise<void>> mTheirInputLabelsProm;
		std::vector<std::future<void>> mTheirInputLabelsFuture;

		std::vector<std::promise<block>> mPsiInputPromise;
		std::vector<std::shared_future<block>> mPsiInputFuture;
		std::vector<std::vector<block>> mMyDecodedKProbeLabels, mTheirInputOffsets;
 
		std::promise<std::vector<block>*> mTheirOutputLabelsProm;
		std::shared_future<std::vector<block>*> mTheirOutputLabelsFuture;
		 
		std::promise<BitVector*> mOutputProm;
		std::future<BitVector*> mOutputFuture;

		u32 mPSIIdxHead;
		std::atomic<i32>  mTransCheckRemaining, mOutputMissCount;
		std::vector<block> mPSIInputBlocks;

		block mOutputLabelSeed;

		block evalCircuit(
			u64 i,
			const Circuit&  cir,
			PRNG& prng,
			const KProbeMatrix& myKprobe,
			std::vector<block>& labels,
			Channel& chl,
#ifdef ADAPTIVE_SECURE
			std::vector<block> adaptiveSecureTableMasks,
			const std::vector<block>& indexArray,
#endif
			Role role,
			Timer& timer);

		/// a matrix of m rows each of size (bucketSize-1) which holds the xor differences between the random ot choice bits of their first circuit and the i'th circuit. 
		std::vector<BitVector> mTheirPermutes; //mTheirDeltas;
		/// the circuits and related material that they generated in the setup phase. we will evaluate these.
		std::vector<CommCircuitPackage*> mTheirCircuits;
		/// the circuits and related material that we generated in the set up phase. they will evaluate these.
		std::vector<CircuitPackage*> mMyCircuits;
		/// these values allow us to translate the output labels we got by evaluating to the common output labels that their chose for their bucket
		std::vector<std::vector<std::array<block, 2>>> mTranlation;
		/// these are the common output labels that we chose for this bucket. they will use their translation values to map to these values.
		std::vector<std::array<block, 2>> mCommonOutput;

		std::vector<u64> mPSIInputPermutes;
		std::mutex mPsiInputMtx;

#ifdef DUALEX_DEBUG
		std::vector<std::array<block, 2>> DEBUG_theirCommonOutput;
		std::vector<std::vector<std::array<block, 2>>> DEBUG_myDecodedInputs;
#endif

	public:
#ifdef ASYNC_PSI
		AsyncPsiSender mPsiSend;
		AsyncPsiReceiver mPsiRecv;
#else
		PsiSender mPsiSend;
		PsiReceiver mPsiRecv;
#endif

	};

}
