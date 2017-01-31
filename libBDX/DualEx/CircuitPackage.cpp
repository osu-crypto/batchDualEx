#include "CircuitPackage.h" 
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Crypto/Commit.h"

namespace osuCrypto {
#ifdef GetMessage
#undef GetMessage
#endif

	CommCircuitPackage::CommCircuitPackage(CommCircuitPackage&& src)
		:
		mIdx(src.mIdx),
		mCircuit(std::move(src.mCircuit)),
		mOTSend(src.mOTSend),
		mOTStartIdx(src.mOTStartIdx),
		mOTCount(src.mOTCount),
		mOutputCommit(src.mOutputCommit),
		mTheirInputCommits(std::move(src.mTheirInputCommits)),
		mMyKProbeInputCommit(std::move(src.mMyKProbeInputCommit))
	{
	}

	CircuitPackage::CircuitPackage(CircuitPackage&& src)
		:
		mIdx(src.mIdx),
		mCircuitSeed(src.mCircuitSeed),
		mCircuit(std::move(src.mCircuit)),
		mOTStartIdx(src.mOTStartIdx),
		mRecvOT(src.mRecvOT),
		mOTRecvChoices(std::move(src.mOTRecvChoices)),
		mKProbeWireSeed(src.mKProbeWireSeed)
#ifdef ADAPTIVE_SECURE
		, mAdaptiveSecureMaskSeed(src.mAdaptiveSecureMaskSeed)
#endif
	{
	}

	void CircuitPackage::init(
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
		)
	{
		mIdx = idx;

		mCircuitSeed = prng.get<block>();

#ifdef ADAPTIVE_SECURE
		mAdaptiveSecureMaskSeed = prng.get<block>(); 

		AES adaptiveSecureMaskKey(mAdaptiveSecureMaskSeed);
		adaptiveSecureMaskKey.ecbEncBlocks(indexArray.data(), adaptiveSecureTableMasks.size(), adaptiveSecureTableMasks.data());

		// Garble the Circuit
		mCircuit.GarbleSend(cir, mCircuitSeed, channel, wireBuff, indexArray, adaptiveSecureTableMasks);
#else
		// Garble the Circuit
		mCircuit.GarbleSend(cir, mCircuitSeed, channel, wireBuff);
#endif
		mKProbeWireSeed = prng.get<block>();

        //std::cout << IoStream::lock 
        //    << "circuit = " << idx 
        //    << " mOutputWires[0][0] = " << mCircuit.mOutputWires[0]
        //    << " mOutputWires[0][1] = " << (mCircuit.mGlobalOffset ^ mCircuit.mOutputWires[0] )
        //    << std::endl << IoStream::unlock;



		mKProbeInputs.resize(theirKProbe.encodingSize());

		assert(eq(indexArray[0], ZeroBlock));
		//std::cout << "kprobe " << mKProbeWireSeed << std::endl;

		AES genKey(mKProbeWireSeed);
		genKey.ecbEncBlocks(indexArray.data(), theirKProbe.encodingSize(), mKProbeInputs.data());

		u64 inputCommitSize = theirKProbe.encodingSize() * 2 * sizeof(Commit);
		std::unique_ptr<ByteStream> buff(new ByteStream(inputCommitSize));
		buff->setp(inputCommitSize);
		Commit* commits = (Commit*)buff->data();

		for (u64 i = 0; i < theirKProbe.encodingSize(); ++i)
		{
			*commits++ = Commit(mKProbeInputs[i]);
			*commits++ = Commit(mKProbeInputs[i] ^ mCircuit.mGlobalOffset);
		}

		channel.asyncSend(std::move(buff));

		commitToOutputs(cir, role, channel); 
	}

	void CircuitPackage::initOT(
		const Circuit& cir,
		Role role,
		Channel& channel,
		const KProbeMatrix& myKProbe,
		BDX_OTExtReceiver& recvOT,
		u64& firstOTIdx)
	{


		//channel.asyncSendCopy((u8*)&firstOTIdx, sizeof(u64));


		mRecvOT = &recvOT;
		mOTStartIdx = firstOTIdx;
		mOTRecvChoices.copy(recvOT.mChoiceBits, firstOTIdx, myKProbe.encodingSize());

		firstOTIdx += myKProbe.encodingSize();

		assert(mOTRecvChoices.size());

		commitToInputs(cir, myKProbe, role, channel);

		mOTInitDoneProm.set_value();
	}
	void CircuitPackage::commitToInputs(
		const Circuit& cir,
		const KProbeMatrix& myKProbe,
		Role role,
		Channel& channel)
	{
		u64 wireIdx = (role == Second) ? cir.Inputs()[0] : 0;
		block labels[2];
		u8 permute;


		BitVector permuteBits;
		myKProbe.decode(mOTRecvChoices, permuteBits);

		//std::unique_lock<std::mutex> lock(Lg::mMtx);

		// for each wire, commit the 1 label first if the random OT choice bit is 1
		// else commit the 0 label first.

		std::unique_ptr<ByteStream> buff(new ByteStream(cir.Inputs()[(u64)role] * 2 * sizeof(Commit)));
		buff->setp(cir.Inputs()[(u64)role] * 2 * sizeof(Commit));
		Commit* commits = (Commit*)buff->data();


		for (u64 i = 0; i < cir.Inputs()[(u64)role]; ++i)
		{
			permute = permuteBits[i];

			labels[0] = mCircuit.mInputWires[wireIdx + i];
			labels[1] = labels[0] ^ mCircuit.mGlobalOffset;
 
			*commits++ = Commit(labels[permute]);
			*commits++ = Commit(labels[1 ^ permute]);
		}
		channel.asyncSend(std::move(buff));
	}

	void CircuitPackage::commitToOutputs(const Circuit& cir, Role role, Channel& channel)
	{
		auto buff = ByteStream(sizeof(block) * 2 * cir.Outputs().size());
		buff.setp(sizeof(block) * 2 * cir.Outputs().size());

		block tweaks[2], enc[2];
		block* hash = (block*)buff.data();

		// hash the output wires and then commit to that. The hash is needed so that
		// when we open them during the psi, they can't learn the xorOffset...

		// set this tweaks to this because 0 and cir.WireCount() tweak values were used in garbling.
		tweaks[0] = _mm_set1_epi64x(2 * cir.WireCount());
		tweaks[1] = _mm_set1_epi64x(3 * cir.WireCount());

		for (auto& out : mCircuit.mOutputWires)
		{
			// compute the hashs of the wires as H(x) = AES_f( x * 2 ^ tweak) ^ (x * 2 ^ tweak)    
			hash[0] = _mm_slli_epi64(out, 1) ^ tweaks[0];
			hash[1] = _mm_slli_epi64(out ^ mCircuit.mGlobalOffset, 1) ^ tweaks[1];

            mAesFixedKey.ecbEncTwoBlocks(hash, enc);
			//AES128::EcbEncTwoBlocks(HalfGtGarbledCircuit::mAesFixedKey, hash, enc);

			hash[0] = hash[0] ^ enc[0]; // H( a0 )
			hash[1] = hash[1] ^ enc[1]; // H( a1 )

			// increment the tweaks
			tweaks[0] = tweaks[0] + OneBlock;
			tweaks[1] = tweaks[1] + OneBlock;

			hash += 2;
			//buff.append(hash[0]);
			//buff.append(hash[1]);
		}
		std::unique_ptr<ByteStream> commitBuff(new ByteStream(sizeof(Commit)));
		commitBuff->setp(sizeof(Commit));

		*((Commit*)commitBuff->data()) = Commit(buff.data(), buff.size());

		channel.asyncSend(std::move(commitBuff));
	}




	void CommCircuitPackage::init(
		const Circuit& cir, 
		const KProbeMatrix& mMyKProbe,
		Channel& chl,
		u64 idx)
	{
		mIdx = idx;
		// receive the garbled gates and translation table
		mCircuit.ReceiveFromGarbler(cir, chl);

		mMyKProbeInputCommit.resize(mMyKProbe.encodingSize());
		chl.recv(mMyKProbeInputCommit.data(), mMyKProbe.encodingSize() * sizeof(Commit) * 2);
		
		// receive one large commit for all of the hashed output labels
		chl.recv(&mOutputCommit, sizeof(Commit));

	}

	void CommCircuitPackage::initOT(
		Channel & chl, 
		const KProbeMatrix & kProbe, 
		BDX_OTExtSender & sendOT, 
		u64& otIdx,
		u64 thierInputSize)
	{

		//ByteStream buff;
		//chl.recv(buff);
		//u64 theirIdx = *(u64 *)buff.data();
		//if (theirIdx != otIdx)
		//	throw std::runtime_error("");

		// for each bit of their input, have them commit to the corresponding input label. they are
		// permuted according to the delta values.
		mTheirInputCommits.clear();
		mTheirInputCommits.resize(thierInputSize);

		chl.recv(mTheirInputCommits.data(), thierInputSize * sizeof(Commit) * 2);
		
		//for (auto& inputComm : mInputCommits)
		//{
		//	chl.recv(inputComm[0]);
		//	chl.recv(inputComm[1]);
		//}

		mOTSend = &sendOT;
		mOTStartIdx = otIdx;
		mOTCount = kProbe.encodingSize();
		otIdx += mOTCount;

		mOTInitDoneProm.set_value();
	}

	const block & CommCircuitPackage::OTSendMsg(u64 idx, u8 bit) const
	{
		assert(idx < mOTCount);
		return mOTSend->GetMessage(mOTStartIdx + idx, bit);
	}


	u8 CircuitPackage::OTRecvChoices(const u64 idx) const
	{
		return mOTRecvChoices[idx];
	}
	const block& CircuitPackage::OTRecvMsg(const u64 idx)const
	{
		assert(idx < mOTRecvChoices.size());
		return mRecvOT->GetMessage(mOTStartIdx + idx);
	}

	void CircuitPackage::open(
		const Circuit& cir,
		Channel& channel,
		Role role,
		block& OTMessageXORSum)
	{
		// send them the seeds so they can decommit and check everything
		channel.asyncSend(&mCircuitSeed, sizeof(block));
		//std::cout << "kk " << mKProbeWireSeed << std::endl; 

		channel.asyncSend(&mKProbeWireSeed, sizeof(block));

#ifdef ADAPTIVE_SECURE
		channel.asyncSend(&mAdaptiveSecureMaskSeed, sizeof(block));

#endif

		// send them the OT messages.
		//channel.asyncSend((u8*)&OTRecvMsg(0), mOTRecvChoices.size() * sizeof(block));
		//std::cout << mOTRecvChoices.size() << std::endl;

		std::unique_ptr<BitVector> buff(new BitVector(mOTRecvChoices));

		channel.asyncSend(std::move(buff));

		const block* otMsgs = &OTRecvMsg(0);
		for (u64 i = 0; i < mOTRecvChoices.size(); ++i)
		{
			OTMessageXORSum = OTMessageXORSum ^ *otMsgs++;
		}

		clear();
	}



	void CommCircuitPackage::open(
		const Circuit& cir,
		const KProbeMatrix& theirKProbe,
		const KProbeMatrix& myKProbe,
		Role role,
		Channel& channel, 
		block& OTMsgXORSum,
		const std::vector<block>& indexArray
#ifdef ADAPTIVE_SECURE
		, std::vector<block> blockBuff
#endif
		)
	{
		block circuitSeed, kProbeWireSeed;

		channel.recv(&circuitSeed, sizeof(block));
		channel.recv(&kProbeWireSeed, sizeof(block));

#ifdef ADAPTIVE_SECURE
		block adaptiveSecureMaskSeed;
		channel.recv(&adaptiveSecureMaskSeed, sizeof(block));

		AES adaptiveSecureMaskKey(adaptiveSecureMaskSeed);
		adaptiveSecureMaskKey.ecbEncBlocks(indexArray.data(), blockBuff.size(), blockBuff.data());

		// re-garble the circuit and check its garbled tables
		mCircuit.Validate(cir, circuitSeed, indexArray, blockBuff);
#else
		// re-garble the circuit and check its garbled tables
		mCircuit.Validate(cir, circuitSeed);
#endif

		assert (blockBuff.size() >= myKProbe.encodingSize());

		assert(eq(indexArray[0], ZeroBlock));
		//std::cout << "kprobe " << kProbeWireSeed << std::endl;


		AES genKey(kProbeWireSeed);
		genKey.ecbEncBlocks(indexArray.data(), myKProbe.encodingSize(), blockBuff.data());

 
		for (u64 i = 0; i < myKProbe.encodingSize(); ++i)
		{
			if (mMyKProbeInputCommit[i][0] != Commit(blockBuff[i]))
				throw std::runtime_error("mMyKProbeInputCommit" LOCATION);
			if (mMyKProbeInputCommit[i][1] != Commit(blockBuff[i] ^ mCircuit.mGlobalOffset))
				throw std::runtime_error("mMyKProbeInputCommit" LOCATION);
		}


		ByteStream buff;
		buff.reserve(mCircuit.mOutputWires.size() * sizeof(block) * 2);
		buff.setp(mCircuit.mOutputWires.size() * sizeof(block) * 2);
		block *hash = (block*)buff.data();

		// hash the output wires and then commit to that. The hash is needed so that
		// when we open them during the psi, they can't learn the xorOffset...
		block tweaks[2], enc[2];
		// set this tweaks to this because 0 and cir.WireCount() tweak values were used in garbling.
		tweaks[0] = _mm_set1_epi64x(2 * cir.WireCount());
		tweaks[1] = _mm_set1_epi64x(3 * cir.WireCount());

		for (auto& out : mCircuit.mOutputWires)
		{
			// compute the hashs of the wires as H(x) = AES_f( x * 2 ^ tweak) ^ (x * 2 ^ tweak)    
			hash[0] = _mm_slli_epi64(out, 1) ^ tweaks[0];
			hash[1] = _mm_slli_epi64(out ^ (mCircuit.mGlobalOffset), 1) ^ tweaks[1];

            mAesFixedKey.ecbEncTwoBlocks(hash, enc);
			//AES128::EcbEncTwoBlocks(HalfGtGarbledCircuit::mAesFixedKey, hash, enc);

			hash[0] = hash[0] ^ enc[0]; // H( a0 )
			hash[1] = hash[1] ^ enc[1]; // H( a1 )

			// increment the tweaks
			tweaks[0] = tweaks[0] + OneBlock;
			tweaks[1] = tweaks[1] + OneBlock;
			
			hash += 2;
		}
		 
		if (mOutputCommit != Commit(buff.data(), buff.size()))
			throw std::runtime_error(LOCATION);

		// validate permuted inputs
		u64 wireIdx = (role == First) ? cir.Inputs()[0] : 0;
		block labels[2];

		BitVector theirOTChoiceBits(theirKProbe.encodingSize());
		channel.recv(theirOTChoiceBits);


		// Check that they committed to their inputs according to their 
		// random ot choice bits
		for (u64 i = 0; i < theirKProbe.encodingSize(); ++i)
		{
			//buff.consume(otMsg);

			OTMsgXORSum = OTMsgXORSum ^ OTSendMsg(i, theirOTChoiceBits[i]);
			//if (eq(OTSendMsg(i,1), otMsg))
			//	theirOTChoiceBits[i] = 1;
			//else if (eq(OTSendMsg(i,0), otMsg))
			//	theirOTChoiceBits[i] = 0;
			//else
			//	throw std::runtime_error("");
		}


		BitVector permuteBits;
		theirKProbe.decode(theirOTChoiceBits, permuteBits);

		for (u64 i = 0; i < permuteBits.size(); ++i)
		{
			labels[0] = mCircuit.mInputWires[wireIdx + i];
			labels[1] = labels[0] ^ mCircuit.mGlobalOffset;
			u8 permute = permuteBits[i];

			if (Commit(labels[permute]) != mTheirInputCommits[i][0])
				throw std::runtime_error("mInputCommits" LOCATION);

			if (Commit(labels[1 ^ permute]) != mTheirInputCommits[i][1])
				throw std::runtime_error("mInputCommits" LOCATION);
		}

		clear();
	}


	void CommCircuitPackage::clear()
	{
		mTheirInputCommits.clear();
		mTheirInputCommits.shrink_to_fit();
		mMyKProbeInputCommit.clear();
		mMyKProbeInputCommit.shrink_to_fit();
		mCircuit.Clear();
	}


	void CircuitPackage::clear()
	{
		mCircuit.Clear();
		mKProbeInputs.clear();
		mKProbeInputs.shrink_to_fit();
	}
}
