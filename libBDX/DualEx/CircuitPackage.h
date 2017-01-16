#pragma once
#include "Circuit/HalfGtGarbledCircuit.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "OT/OTExtReceiver.h"
#include "OT/OTExtSender.h"
#include "cryptoTools/Network/Channel.h"
//#include "cryptoTools/Common/ArrayView.h"
#include "cryptoTools/Crypto/Commit.h"
#include "Circuit/KProbeResistant.h"
#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto {

	class CircuitPackage
	{
	public:
		CircuitPackage() : mOTInitDoneFutr(mOTInitDoneProm.get_future()){};
		CircuitPackage(const CircuitPackage&) = delete;
		
		CircuitPackage(CircuitPackage&&);


		void init(
			const Circuit& cir,
			Role role,
			PRNG& prng,
			Channel& channel,
			u64 idx,
			const KProbeMatrix& theirKProbe,
			std::vector<block>& wireBuff,
			const std::vector<block>& indexArray
#ifdef ADAPTIVE_SECURE
			, std::vector<block> adaptiveSecureTableMasks
#endif
			);

		void initOT(
			const Circuit& cir,
			Role role,
			Channel& channel,
			const KProbeMatrix& mKProbe,
			BDX_OTExtReceiver& recvOT,
			u64& OTIdx);


		void open(
			const Circuit& cir,
			Channel& channel, 
			Role role,
			block& OTMessageXORSum);

		void clear();

		u64 mIdx;
		block mCircuitSeed, mKProbeWireSeed;
		HalfGtGarbledCircuit mCircuit;
		u64 mOTStartIdx;

		std::vector<block> mKProbeInputs;

		u8 OTRecvChoices(const u64 idx) const;
		const block& OTRecvMsg(const u64 idx) const;
		//std::vector<block> mOTRecvMsg;


		std::promise<void> mOTInitDoneProm;
		std::future<void> mOTInitDoneFutr;


	private:
		void commitToInputs(
			const Circuit& cir,
			const KProbeMatrix& myKProbe, 
			Role role,
			Channel& channel);

		void commitToOutputs(const Circuit& cir, Role role, Channel& channel);

	public:
		const BDX_OTExtReceiver* mRecvOT;
		BitVector mOTRecvChoices;

#ifdef ADAPTIVE_SECURE
		block mAdaptiveSecureMaskSeed;
#endif
	};
 
	class CommCircuitPackage
	{

	public:

		CommCircuitPackage() : mOTInitDoneFutr(mOTInitDoneProm.get_future()) {};
		CommCircuitPackage(const CommCircuitPackage&) = delete;

		CommCircuitPackage(CommCircuitPackage&&);

		void init(
			const Circuit& cir,
			const KProbeMatrix& mMyKProbe,
			Channel& chl,
			u64 idx);

		void initOT(
			Channel& chl,
			const KProbeMatrix& mKProbe,
			BDX_OTExtSender& sendOT,
			u64& otIdx,
			u64 thierInputSize);

		void open(
			const Circuit& cir,
			const KProbeMatrix& theirKProbe,
			const KProbeMatrix& myKProbe,
			Role role, 
			Channel& chl,
			block& OTMsgXORSum,
			const std::vector<block>& indexArray
#ifdef ADAPTIVE_SECURE
			, std::vector<block> adaptiveSecureTableMasks
#endif
			);
		 
		void clear();

		std::promise<void> mOTInitDoneProm;
		std::future<void> mOTInitDoneFutr;

		u64 mIdx;
		HalfGtGarbledCircuit mCircuit;
		const block& OTSendMsg(u64 idx, u8 bit)const; 
	private:
		const BDX_OTExtSender* mOTSend;
		u64 mOTStartIdx, mOTCount;
	public: 
		Commit mOutputCommit;
		std::vector<std::array<Commit, 2>> mTheirInputCommits, mMyKProbeInputCommit;
		
	};

}