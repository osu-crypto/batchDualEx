#include "Bucket.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/ArrayView.h"

//#define DUALEX_DEBUG  

namespace osuCrypto
{


	Bucket::Bucket()
		:
		mInputFuture(mInputPromise.get_future()),
		mTheirInputCorrectionFuture(mTheirInputCorrectionPromise.get_future()),
		//mPsiInputsFuture(mPsiInputsPromise.get_future()),
		mTheirDeltasFuture(mTheirDeltasProm.get_future()),
		mMyCircuitsBucketedFuture(mMyCircuitsBucketedProm.get_future()),
		//mPSIInputCommittedFuture(mPSIInputCommittedProm.get_future()),
		mTheirOutputLabelsFuture(mTheirOutputLabelsProm.get_future()),
		mOutputFuture(mOutputProm.get_future()),
		mTranslationCheckDoneFuture(mTranslationCheckDoneProm.get_future()),
		mOutputMissCount(0)
	{
	}


	Bucket::~Bucket()
	{
	}


	void Bucket::initRecv(
		const Circuit& cir,
		Channel& chl,
		KProbeMatrix& theirKProbe,
		u64 bucketSize,
		u64 psiSecParam,
		std::vector<u64>::iterator& cirIdxIter,
		std::vector<CommCircuitPackage>& circuits,
        BDX_OTExtSender& otSend,
		PRNG& prng,
		u64& otIdx,
		Role role)
	{
		mPsiSend.init(bucketSize, psiSecParam, chl, otSend, otIdx, prng);

        mEvalOutput.resize(bucketSize);
		mPSIInputBlocks.resize(bucketSize);
		mPSIIdxHead = 0;
		mPsiInputPromise.resize(bucketSize);
		mPsiInputFuture.reserve(bucketSize);
		mTransCheckRemaining = (i32)bucketSize;
		mPSIInputPermutes.resize(bucketSize);
		mTheirCircuits.reserve(bucketSize);
		mOutputs.resize(bucketSize);
		mTheirInputLabelsProm.resize(bucketSize);
		mTheirInputLabelsFuture.reserve(bucketSize);
		mTranlation.resize(bucketSize);
		for (u64 i = 0; i < bucketSize; ++i)
		{
			mPSIInputPermutes[i] = i;
            mEvalOutput[i].resize(cir.Outputs().size());
			mTranlation[i].resize(cir.Outputs().size());
			chl.recv(mTranlation[i].data(), mTranlation[i].size() * sizeof(block) * 2);

			mPsiInputFuture.emplace_back(mPsiInputPromise[i].get_future());
			mTheirInputLabelsFuture.emplace_back(mTheirInputLabelsProm[i].get_future());

			mTheirCircuits.push_back(&(circuits[*(cirIdxIter++)]));
			mTheirCircuits[i]->mOTInitDoneFutr.get();

			mOutputs[i].resize(cir.Outputs().size());
		}
		std::shuffle(mPSIInputPermutes.begin(), mPSIInputPermutes.end(), prng);

		mTheirPermutes.resize(bucketSize - 1);
		BitVector delta(theirKProbe.encodingSize());
		for (u64 i = 0; i < mTheirPermutes.size(); ++i)
		{
			chl.recv(delta);
			theirKProbe.decode(delta, mTheirPermutes[i]);
		}


		mTheirDeltasProm.set_value();



	}

	void Bucket::initSend(
		const Circuit & cir,
		Channel& chl,
		u64 bucketSize,
		u64 psiSecParam,
		Role role,
		std::vector<CircuitPackage>& circuits,
		std::vector<u64>::iterator & cirIdxIter,
		PRNG& prng,
		const KProbeMatrix& theirKprobe,
		const KProbeMatrix& myKprobe,
		BDX_OTExtReceiver & otRecv,
		u64& otIdx,
		const std::vector<block>& indexArray)
	{
		mPsiRecv.init(bucketSize, psiSecParam, chl, otRecv, otIdx);

		mTheirInputCorrection.reset(cir.Inputs()[1 ^ role]);

		block tweaks[2], enc[2];


		// TODO("Change this to a single call to AES");
		// compute the bucket wide output values
		mOutputLabelSeed = prng.get<block>();
		//PRNG outputGen(mOutputLabelSeed);
		mCommonOutput.resize(cir.Outputs().size());
		//for (auto& wire : mCommonOutput)
		//{
		//	wire[0] = outputGen.get<block>();
		//	wire[1] = outputGen.get<block>();
		//}
		AES outGen(mOutputLabelSeed);
		outGen.ecbEncBlocks(indexArray.data(),  mCommonOutput.size() * 2, (block*)mCommonOutput.data());

		// for each circuit, compute the output translation values that allows
		//   the evaluator to get to a common bucket wire set of output labels
		mMyCircuits.reserve(bucketSize);
		for (u64 b = 0; b < bucketSize; ++b)
		{
			mMyCircuits.emplace_back(&(circuits[*(cirIdxIter++)]));
		}

		mMyCircuitsBucketedProm.set_value();



		u64 translationSize = 2 * sizeof(block) * cir.Outputs().size();
		for (u64 b = 0; b < bucketSize; ++b)
		{

			//std::cout << "P" << (int)role << " " << mMyCircuits[b]->mIdx << std::endl;

			mMyCircuits[b]->mOTInitDoneFutr.get();

			auto buff = std::unique_ptr<ByteStream>(new ByteStream(translationSize));
			buff->setp(translationSize);

			block* translationValues = (block*)buff->data();

			// set this tweaks to this because 0 and cir.WireCount() tweak values were used in garbling.
			tweaks[0] = _mm_set1_epi64x(2 * cir.WireCount());
			tweaks[1] = _mm_set1_epi64x(3 * cir.WireCount());
			block xorOffset = mMyCircuits[b]->mCircuit.mGlobalOffset;

			for (u64 i = 0; i < cir.Outputs().size(); ++i, translationValues += 2)
			{
				// hash the wire labels to destroy the xor offset
				// compute the hashs of the wires as H(x) = AES_f( x * 2 ^ tweak) ^ (x * 2 ^ tweak)    
				translationValues[0] = _mm_slli_epi64(mMyCircuits[b]->mCircuit.mOutputWires[i], 1) ^ tweaks[0];
				translationValues[1] = _mm_slli_epi64(mMyCircuits[b]->mCircuit.mOutputWires[i] ^ (xorOffset), 1) ^ tweaks[1];

                mAesFixedKey.ecbEncTwoBlocks(translationValues, enc);
				//AES128::EcbEncTwoBlocks(HalfGtGarbledCircuit::mAesFixedKey, );

				translationValues[0] = translationValues[0] ^ enc[0]; // H( a0 )
				translationValues[1] = translationValues[1] ^ enc[1]; // H( a1 )

											// increment the tweaks
				tweaks[0] = tweaks[0] + OneBlock;
				tweaks[1] = tweaks[1] + OneBlock;


				//block b0 = translationValues[0];
				//block b1 = translationValues[1];

				translationValues[0] = translationValues[0] ^ mCommonOutput[i][0];
				translationValues[1] = translationValues[1] ^ mCommonOutput[i][1];

				//std::cout << "co[" << i << "][0] " << b0 << " = O " << mCommonOutput[i][0] << " + T " << translationValues[0] << std::endl;
				//std::cout << "co[" << i << "][1] " << b1 << " = O " << mCommonOutput[i][1] << " + T " << translationValues[1] << std::endl;

			}
			chl.asyncSend(std::move(buff));
		}

		for (u64 j = 1; j < bucketSize; ++j)
		{

			std::unique_ptr<BitVector>delta(new BitVector(mMyCircuits[0]->mOTRecvChoices));
			*delta ^= mMyCircuits[j]->mOTRecvChoices;

			chl.asyncSend(std::move(delta));
		}


	}

	void Bucket::initKProbeInputSend(const Circuit & cir, Channel & chl, KProbeMatrix & theirKProbe, PRNG & prng, Role role, const std::vector<block>& indexArray)
	{
		// wait for their delta values to be put in this bucket...
		mTheirDeltasFuture.get();

		u64 start[2] = { 0 , cir.Inputs()[0] };

		std::unique_ptr<ByteStream> buff(new ByteStream(sizeof(block) * 2 * theirKProbe.encodingSize()));
                auto buffIter = buff->getArrayView<block>().begin();

		std::array<const block*, 2> OTMsgs = { { &mTheirCircuits[0]->OTSendMsg(0, 0), &mTheirCircuits[0]->OTSendMsg(0, 1) } };

		block xorOffset = mMyCircuits[0]->mCircuit.mGlobalOffset;


		mTheirInputOffsets.resize(mMyCircuits.size());
		mTheirInputOffsets[0].resize(cir.Inputs()[1 ^ role]);
		theirKProbe.decode(mMyCircuits[0]->mKProbeInputs, mTheirInputOffsets[0]);

		//{

		for (u64 t = 0; t < theirKProbe.encodingSize(); ++t)
		{
			//std::cout << "P" << (int)(1 ^ role) << "'s En kprobe i[0][" << t << "] " << (encodedZeroLabels[t]) << "  " << (encodedZeroLabels[t] ^ xorOffset) << std::endl;
            *buffIter++ = (OTMsgs[0][t] ^ mMyCircuits[0]->mKProbeInputs[t]);
            *buffIter++ = (OTMsgs[1][t] ^ mMyCircuits[0]->mKProbeInputs[t] ^ xorOffset);
		}
		mMyCircuits[0]->mKProbeInputs.clear();

		//std::cout << std::endl;
		chl.asyncSend(std::move(buff));
		//
		   //for (u64 t = 0; t < cir.Inputs()[1 ^ role]; ++t)
		   //{

		   //	std::cout << "P" << (int)(1 ^ role) << "'s decoded kprobe  i[" << 0 << "][" << t << "] " << (mTheirInputOffsets[0][t]) << "  " << (mTheirInputOffsets[0][t] ^ xorOffset) << std::endl;

		   //}
	   //}

		for (u64 i = 0, b = 1; i < mTheirPermutes.size(); ++i, ++b)
		{

			buff.reset(new ByteStream(sizeof(block) * 2 * theirKProbe.encodingSize()));
            buffIter = buff->getArrayView<block>().begin();

			OTMsgs[0] = &mTheirCircuits[b]->OTSendMsg(0, 0);
			OTMsgs[1] = &mTheirCircuits[b]->OTSendMsg(0, 1);

			xorOffset = mMyCircuits[b]->mCircuit.mGlobalOffset;

			mTheirInputOffsets[b].resize(cir.Inputs()[1 ^ role]);
			theirKProbe.decode(mMyCircuits[b]->mKProbeInputs, mTheirInputOffsets[b]);

			//std::unique_lock<std::mutex> lock(Lg::mMtx);
			for (u64 t = 0; t < theirKProbe.encodingSize(); ++t)
			{
				//u8 bit = mTheirDeltas[i][t];

				//std::cout << "P" << (int)(1 ^ role) << "'s En kprobe i["<< b <<"][" << t << "] " << (encodedZeroLabels[t]) << "  " << (encodedZeroLabels[t] ^ xorOffset) << std::endl;


				*buffIter ++ =(OTMsgs[0][t] ^ mMyCircuits[b]->mKProbeInputs[t]);
				*buffIter ++ =(OTMsgs[1][t] ^ mMyCircuits[b]->mKProbeInputs[t] ^ xorOffset);
			}
			mMyCircuits[b]->mKProbeInputs.clear();
			//std::cout << std::endl;

			chl.asyncSend(std::move(buff));

			//{
			//	//std::unique_lock<std::mutex> lock(Lg::mMtx);
			//	for (u64 t = 0; t < cir.Inputs()[1 ^ role]; ++t)
			//	{

			//		std::cout << "P" << (int)(1 ^ role) << "'s decoded kprobe  i[" << b << "][" << t << "] " << (mTheirInputOffsets[b][t]) << "  " << (mTheirInputOffsets[b][t] ^ xorOffset) << std::endl;

			//	}
			//}
		}
	}

	void Bucket::initKProbeInputRecv(const Circuit & cir, Channel & chl, KProbeMatrix & myKProbe, PRNG & prng, Role role)
	{
		mMyCircuitsBucketedFuture.get();

		std::vector<block> maskedLabels(2 * myKProbe.encodingSize());
		std::vector<block> labels(myKProbe.encodingSize());

		mMyDecodedKProbeLabels.resize(mTheirCircuits.size());

		mInputCorrectionString.reset(new BitVector(cir.Inputs()[role]));
		myKProbe.decode(mMyCircuits[0]->mOTRecvChoices, *mInputCorrectionString);

		for (u64 i = 0; i < mTheirCircuits.size(); ++i)
		{
			chl.recv(maskedLabels.data(), sizeof(block) * maskedLabels.size());


			//std::unique_lock<std::mutex> lock(Lg::mMtx);

			for (u64 t = 0; t < myKProbe.encodingSize(); ++t)
			{
				u8 c = mMyCircuits[i]->OTRecvChoices(t);

				labels[t] = maskedLabels[2 * t + c] ^ mMyCircuits[i]->OTRecvMsg(t);

				if (Commit(labels[t]) != mTheirCircuits[i]->mMyKProbeInputCommit[t][c])
					throw std::runtime_error(LOCATION);

				//std::cout << "P" << (int)(role) << "'s En kprobe r[" << i << "][" << t << "] " << labels[t] << "  "  << (u32)c << std::endl;

			}
			mMyDecodedKProbeLabels[i].resize(cir.Inputs()[role]);

			myKProbe.decode(labels, mMyDecodedKProbeLabels[i].begin());


			BitVector myPermutes;
			myKProbe.decode(mMyCircuits[i]->mOTRecvChoices, myPermutes);
			//std::unique_lock<std::mutex> lock(Lg::mMtx);


			//for (u64 j = 0; j < mMyDecodedKProbeLabels[i].size(); ++j)
			//{

			//	std::cout << "P" << (int)role << "'s kprobeLabels [" << i << "][" << j << "]  " << (int)myPermutes[j] << "  " << mMyDecodedKProbeLabels[i][j] << std::endl;

			//}
		}
	}



	void Bucket::evaluate(
		const Circuit&  cir,
		const KProbeMatrix& theirKprobe,
		const KProbeMatrix& myKprobe,
		PRNG& prng,
		Channel& chl,
		Role role,
		const BitVector& input,
		std::vector<std::vector<block>>& labels,
		Timer& timer)
	{

		// xor input into with the random ots choice bits

		//{


			//std::cout << "P" << (int)role << " i.cor r " << *mInputCorrectionString << "+ i " << input << "= c ";

		*mInputCorrectionString ^= input;


		chl.asyncSend(std::move(mInputCorrectionString));

		//}
		//std::cout << "P" << (int)role << " sent input correction" << std::endl;


		mTheirInputCorrectionFuture.get();

		//std::cout << "P" << (int)role << " received input correction" << std::endl;

		for (u64 j = 0; j < mTheirCircuits.size(); ++j) mTheirInputLabelsFuture[j].get();

		u64 start[2] = { 0 , cir.Inputs()[0] };
		for (u64 i = 0, wireIdx = start[1 ^ role]; i < cir.Inputs()[1 ^ role]; ++i, ++wireIdx)
		{
			Commit comm(labels[0][wireIdx]);


			//std::cout << "P" << (int)(1 ^ role) << " il chck [0][" << i << "] " << labels[0][wireIdx] << std::endl;

			// this is the xor of their actual i'th input bit and the i'th bit of
			// what their random ot choice bits decode to.
			u8 phi = mTheirInputCorrection[i];
			if (comm != mTheirCircuits[0]->mTheirInputCommits[i][phi])
			{
				std::cout << "input sender's input commit failed at cirIdx 0 (" << mTheirCircuits[0]->mIdx << ") input idx " << i << ". Their permute bit " << (int)(phi) << std::endl;

				std::cout << "their input correction " << mTheirInputCorrection << std::endl;

				std::cout << "L[0][" << wireIdx << "] " << labels[0][wireIdx] << "  ( " << comm << " != " << mTheirCircuits[0]->mTheirInputCommits[i][phi] << std::endl;



				throw std::runtime_error(LOCATION);
			}
			// the rest of the inputs should decommit according to the permute order
			// specified their k-probe matrix * delta = permuteTranspose.
			for (u64 j = 1; j < mTheirCircuits.size(); ++j)
			{
				Commit commi(labels[j][wireIdx]);

				u8 delta = mTheirPermutes[j - 1][i];
				if (commi != mTheirCircuits[j]->mTheirInputCommits[i][delta ^ phi])
				{
					std::cout << "input sender's input commit failed at cirIdx " << j << " (" << mTheirCircuits[j]->mIdx << ") input idx " << i << ". Their permute bit " << (int)(delta ^ phi) << " = " << (int)delta << " ^ " << (int)phi << std::endl;

					std::cout << "their input correction " << mTheirInputCorrection << std::endl
						<< "their delta[i]         " << mTheirPermutes[j - 1] << std::endl;

					std::cout << "L[" << j << "][" << wireIdx << "] " << labels[j][wireIdx] << "  ( " << commi << " != " << mTheirCircuits[j]->mTheirInputCommits[i][delta ^ phi] << std::endl;

					throw std::runtime_error(LOCATION);
				}
			}
		}

	}

	block Bucket::evalCircuit(
		u64 b,
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
		Timer& timer)
	{
		block hash[2];
		block enc[2];
		block tweaks[2];
		block psiInput, adaptiveSecureSeed;
		u64 start[2] = { 0 , cir.Inputs()[0] };

#ifdef DUALEX_DEBUG


		BitVector theirInput(cir.Inputs()[1 ^ role]);
		chl.recv(theirInput);

		ByteStream debugBuff;
		chl.recv(debugBuff);
		block theirXorOffset;
		debugBuff.consume(theirXorOffset);

		std::vector<block> debug_zeroWireLabels(cir.InputWireCount());
		std::vector < std::array<block, 2>> DEBUG_theirCommonOutput(cir.OutputCount());
		for (auto& wire : debug_zeroWireLabels) debugBuff.consume(wire);
		for (auto& wire : DEBUG_theirCommonOutput)
		{
			debugBuff.consume(wire[0]);
			debugBuff.consume(wire[1]);
		}


		u64 cirIdx2;
		chl.recv(&cirIdx2, sizeof(u64));

		if (cirIdx2 != mTheirCircuits[b]->mIdx)
			throw std::runtime_error("");

#endif

#ifdef ADAPTIVE_SECURE 

		//std::cout << "waiting for adapt seed @" << b  << " from P" << (int)(1 - role) << "  on channel " << chl.Name() << std::endl;

		chl.recv(&adaptiveSecureSeed, sizeof(block));

		timer.setTimePoint("AdaptiveSeedReceived");
		//std::cout << "got for adapt seed for cir" << mTheirCircuits[b]->mIdx << " from P" << (int)(1 - role) << "  on channel " << chl.Name() << std::endl;
		AES adaptiveSecureMaskKey(adaptiveSecureSeed);
		adaptiveSecureMaskKey.ecbEncBlocks( indexArray.data(), adaptiveSecureTableMasks.size(), adaptiveSecureTableMasks.data());
		timer.setTimePoint("AdativeSecureMaskGen");

#endif

		// receive their labels.
		auto label = labels.data() + start[1 ^ role];
		chl.recv(label, cir.Inputs()[1 ^ role] * sizeof(block));

		timer.setTimePoint("theirInputs");
		//{
		//	for (u64 i = 0; i < cir.Inputs()[1 ^ role]; ++i)
		//	{
		//		std::cout << "recv P" << (int)(1 ^ role) << "'s thr lb[" << b << "][" << i << "] " << *label++ << std::endl;
		//	}
		//}

		mTheirInputLabelsProm[b].set_value();



		// receive out label correction
		chl.recv(labels.data() + start[role], cir.Inputs()[role] * sizeof(block));
		timer.setTimePoint("myInputs");

		//{

		for (u64 i = 0, idx = start[role]; i < mMyDecodedKProbeLabels[b].size(); ++i, ++idx)
		{
			//block blk = mMyDecodedKProbeLabels[b][i] ^ labels[idx];

			//std::cout << "recv P" << (int)(role) << "'s own lb[" << b << "][" << i << "] " << blk << "  = " << mMyDecodedKProbeLabels[b][i] << "  +  " << labels[idx] << std::endl;

			labels[idx] = mMyDecodedKProbeLabels[b][i] ^ labels[idx];
		}
		

        // copy in any extra wire labels that are set by some external source (RAM)

        for (u64 i = 0; i < mCopyInLabelIdxs.size(); ++i)
        {

            labels[mCopyInLabelIdxs[i]] = mCopyInLabels[b][i];
        }



#ifdef DUALEX_DEBUG

		std::array<block, 2> correction{ {ZeroBlock, theirXorOffset} };

		for (u64 i = 0, idx = start[1 ^ role]; i < cir.Inputs()[1 ^ role]; ++i, ++idx)
		{
			if (neq(labels[idx], debug_zeroWireLabels[idx] ^ correction[theirInput[i]]))
				throw std::runtime_error("");
		}

		const BitVector& myInput = *mInputFuture.get();

		for (u64 i = 0, idx = start[role]; i < mMyDecodedKProbeLabels[b].size(); ++i, ++idx)
		{
			if (neq(labels[idx], debug_zeroWireLabels[idx] ^ correction[myInput[i]]))
				throw std::runtime_error("");
		}
#endif



		//std::cout << "evaluating cir" << mTheirCircuits[b]->mIdx << " from P" << (int)(1 - role) << std::endl;

#ifdef ADAPTIVE_SECURE 
		mTheirCircuits[b]->mCircuit.evaluate(cir, labels, adaptiveSecureTableMasks);
#else
		mTheirCircuits[b]->mCircuit.evaluate(cir, labels);
#endif
		//timer.setTimePoint("evaluated");

		// set this tweaks to this because 0 and cir.WireCount() tweak values were 
		// used in garbling.
		tweaks[0] = _mm_set1_epi64x(2 * cir.WireCount());
		tweaks[1] = _mm_set1_epi64x(3 * cir.WireCount());

		// clear the psi value, as it will be the xor of all output blocks in both direction
		psiInput = ZeroBlock;

		// for each label, hash it and xor it into the psi value along with our corresponding bucket wide output label
		for (u64 i = 0; i < cir.Outputs().size(); ++i)
		{
			// compute the hashs of the wires as H(x) = AES_f( x * 2 ^ tweak) ^ (x * 2 ^ tweak)    
			hash[0] = _mm_slli_epi64(labels[cir.Outputs()[i]], 1) ^ tweaks[0];
			hash[1] = _mm_slli_epi64(labels[cir.Outputs()[i]], 1) ^ tweaks[1];

            mAesFixedKey.ecbEncTwoBlocks(hash, enc);

			hash[0] = hash[0] ^ enc[0]; // H( a0 )
			hash[1] = hash[1] ^ enc[1]; // H( a1 )

			// increment the tweaks
			tweaks[0] = tweaks[0] + OneBlock;
			tweaks[1] = tweaks[1] + OneBlock;


			// use the permute bit and the circuits translation table to decide on the truth value.
			mOutputs[b][i] = PermuteBit(labels[cir.Outputs()[i]]) ^ mTheirCircuits[b]->mCircuit.mTranslationTable[i];
			u8 bit = mOutputs[b][i];



			block theirCommonOutput = hash[bit] ^ mTranlation[b][i][bit];

            mEvalOutput[b][i] = theirCommonOutput;

#ifdef DUALEX_DEBUG
			if (theirCommonOutput != DEBUG_theirCommonOutput[i][bit])
				throw std::runtime_error("");
#endif
			// xor into the psi value the evaluated label xor the translation and our corresponding common output wire value.
			block common = theirCommonOutput ^ mCommonOutput[i][bit];
			//std::cout << "O[" << (int)role << "][" << b << "][" << i << "] = " << common << " = " << theirCommonOutput << " + " << mCommonOutput[i][bit] << "  " << (int)bit << std::endl;

			psiInput = psiInput ^ common;

		}


		timer.setTimePoint("evaluated");

		return psiInput;
		//mPsiSend.mCommitedFuture.get();



		//std::cout << "psi[" << (int)role << "][" << b << "] " << psiInput << " " << mOutputs[b] << std::endl;
		//mPsiInputPromise[b].set_value(psiInput);

		//std::cout << "psi input for cir " << mTheirCircuits[b]->mIdx << " from P" << (int)(1 - role) << std::endl;

		}

	void Bucket::sendCircuitInputs(
		const Circuit&  cir,
		const BitVector & input,
		Role role,
		Channel& chl,
		u64 circuitOffset,
		u64 circuitStep)
	{
		u64 start[2] = { 0 , cir.Inputs()[0] };



		// now send over my inputs. These will in turn be checked against the input commitments 
		// and validated their decommitments are consistent with the delta value i claimed in the 
		// setup phase.
		std::array<block, 2> corrects{ {ZeroBlock, ZeroBlock} };


		mTheirInputCorrectionFuture.get();

		for (u64 cirIdx = circuitOffset; cirIdx < mMyCircuits.size(); cirIdx += circuitStep)
		{


#ifdef DUALEX_DEBUG
			std::unique_ptr<ByteStream> DEBUG_Buff(new ByteStream());

			chl.asyncSendCopy(input);

			DEBUG_Buff->append(mMyCircuits[cirIdx]->mCircuit.mGlobalOffset);

			for (u64 i = 0; i < cir.InputWireCount(); ++i)
				DEBUG_Buff->append(mMyCircuits[cirIdx]->mCircuit.mInputWires[i]);
			for (u64 i = 0; i < cir.OutputCount(); ++i)
			{
				DEBUG_Buff->append(mCommonOutput[i][0]);
				DEBUG_Buff->append(mCommonOutput[i][1]);
			}
			chl.asyncSend(std::move(DEBUG_Buff));


			TODO("remove");
			chl.asyncSend(&mMyCircuits[cirIdx]->mIdx, sizeof(u64));
#endif

#ifdef ADAPTIVE_SECURE
			//std::cout << "sending adapt seed for cir" << mMyCircuits[cirIdx]->mIdx << " to P" << (int)(1 - role) << "  on channel " << chl.Name() << std::endl;

			chl.asyncSend(&mMyCircuits[cirIdx]->mAdaptiveSecureMaskSeed, sizeof(block));
#endif



			std::unique_ptr<ByteStream> buff(new ByteStream(cir.Inputs()[role] * sizeof(block)));
			buff->setp(cir.Inputs()[role] * sizeof(block));
			block* inputLabels = (block*)buff->data();

			block* myLabels = &mMyCircuits[cirIdx]->mCircuit.mInputWires[start[role]];
			corrects[1] = mMyCircuits[cirIdx]->mCircuit.mGlobalOffset;

			for (u64 i = 0; i < cir.Inputs()[role]; ++i, ++myLabels, ++inputLabels)
			{

				// use myLabels as storage for the corrected labels and just send. saves a data read.
				*inputLabels = *myLabels ^ corrects[input[i]];

				//std::cout << "sending P" << (int)role << " my il[" << i << "] " << *inputLabels << std::endl;
			}
			//chl.asyncSend(myLabels, cir.Inputs()[role] * sizeof(block));
			chl.asyncSend(std::move(buff));
		}




		for (u64 cirIdx = circuitOffset; cirIdx < mMyCircuits.size(); cirIdx += circuitStep)
		{



			u64 theirInputSize = cir.Inputs()[1 ^ role];

			std::unique_ptr<ByteStream> buff(new ByteStream(cir.Inputs()[1 ^ role] * sizeof(block)));
			buff->setp(cir.Inputs()[role] * sizeof(block));
			block* inputLabels = (block*)buff->data();

			corrects[1] = mMyCircuits[cirIdx]->mCircuit.mGlobalOffset;
			block* theirKProbeLabels = mTheirInputOffsets[cirIdx].data();
			block* circuitLabels = &mMyCircuits[cirIdx]->mCircuit.mInputWires[start[1 ^ role]];


			for (u64 t = 0; t < theirInputSize; ++t, ++theirKProbeLabels, ++circuitLabels, ++inputLabels)
			{

				if (cirIdx)
				{
					*inputLabels = *theirKProbeLabels ^ *circuitLabels  ^ corrects[mTheirInputCorrection[t] ^ mTheirPermutes[cirIdx - 1][t]];
				}
				else
				{
					*inputLabels = *theirKProbeLabels ^ *circuitLabels  ^ corrects[mTheirInputCorrection[t]];
				}

				//std::cout << "sending P" << (int)(1 ^ role) << " their il[" << t << "] " << *theirKProbeLabels << "  " << (*theirKProbeLabels ^ corrects[1]) << "  -> " << *circuitLabels << " " << (*circuitLabels ^ corrects[1]) << "   (" << *inputLabels << ")" << std::endl;

			}

			//chl.asyncSend(theirLabels, sizeof(block) * theirInputSize);
			chl.asyncSend(std::move(buff));
		}

	}

	///<summary> OpenTranslation
	///This function tries to ensure that all output map to the same 
	///bucket wide output labels. We open each of the circuits output
	///commitments and then do the translation to the common bucket wide
	///output values, if the any "true" or "false" wires don't all map to 
	///their respective values, we abort.  
	///<para>cir - the object that describes the structure of the circuit in question </para>
	///<para>labels - the full set of wire labels obtained from evaluating each circuit. </para>
	///<para>chl - </para>
	///</summary>
	void Bucket::openTranslation(
		const Circuit& cir,
		Channel& chl)
	{


		// block until the PSI has been committed
		//mPSIInputCommittedFuture.get();

		chl.asyncSend(&mOutputLabelSeed, sizeof(block));
		//}

	}

	void Bucket::checkTranslation(
		const Circuit& cir,
		u64 cirIdx,
		std::vector<block>& wireBuff,
		Role role)
	{
		//ByteStream buff;

		std::vector<block>& theirCommonOutLabels = *mTheirOutputLabelsFuture.get();
		assert(wireBuff.size() >= cir.OutputCount() * 2);



		block* translation = mTranlation[cirIdx][0].data();
		auto commonOut = theirCommonOutLabels.data();
		auto out = wireBuff.data();

		for (u64 i = 0; i < cir.Outputs().size(); ++i)
		{
			out[0] = commonOut[0] ^ translation[0]; // mTranlation[b][i][0];
			out[1] = commonOut[1] ^ translation[1]; // mTranlation[b][i][0];

			out += 2;
			commonOut += 2;
			translation += 2;
			//TODO("check that the wire label we evaluated to is one of these");
		}

		if (Commit((u8*)wireBuff.data(), cir.OutputCount() * 2 * sizeof(block)) != mTheirCircuits[cirIdx]->mOutputCommit)
			throw std::runtime_error(LOCATION);

		u64 rem = --mTransCheckRemaining;

		if (rem == 0)
			mTranslationCheckDoneProm.set_value();
	}

	void Bucket::Clear()
	{
        mCommonOutput.clear();
        mCommonOutput.shrink_to_fit();
		//mTheirDeltas.clear();
        mOutputs.clear();
        mOutputs.shrink_to_fit();
        mTranlation.clear();
        mTranlation.shrink_to_fit();

		for (u64 i = 0; i < mMyCircuits.size(); ++i)
		{
			mTheirCircuits[i]->clear();
			mMyCircuits[i]->clear();

            mEvalOutput[i].resize(0);
            mEvalOutput[i].shrink_to_fit();
		}

        mMyCircuits.clear();
        mMyCircuits.shrink_to_fit();
        mTheirCircuits.clear();
        mTheirCircuits.shrink_to_fit();
        mCommonEvalOutput.clear();
        mCommonEvalOutput.shrink_to_fit();


	}


    void Bucket::getGarbledOutput(
        const ArrayView<block>& dest)
    {

#ifndef NDEBUG
        if (dest.size() != mCommonEvalOutput.size())
            throw std::runtime_error("Expecting dest to have the correct size.\n " LOCATION);
#endif // !NDEBUG


        memcpy(dest.data(), mCommonEvalOutput.data(), dest.size() * sizeof(block));
    }


    void Bucket::getGarbledOutput(
        const ArrayView<std::array<block, 2>>& dest)
    {

#ifndef NDEBUG
        if (dest.size() != mCommonOutput.size())
            throw std::runtime_error("Expecting dest to have the correct size.\n " LOCATION);
#endif // !NDEBUG


        memcpy(dest.data(), mCommonOutput.data(), dest.size() * sizeof(block) * 2);
    }

    void Bucket::getGarbledOutput(u64 circuitIdx, const ArrayView<block>& dest)
    {
#ifndef NDEBUG
        if (dest.size() != mCommonOutput.size())
            throw std::runtime_error("Expecting dest to have the correct size.\n " LOCATION);
#endif // !NDEBUG


        memcpy(dest.data(), mEvalOutput.data(), dest.size() * sizeof(block));

    }

    void Bucket::getGarbledOutput(u64 circuitIdx, const ArrayView<block>& dest, block & freeXorOffset)
    {
#ifndef NDEBUG
        if (dest.size() != mCommonOutput.size())
            throw std::runtime_error("Expecting dest to have the correct size.\n " LOCATION);
#endif // !NDEBUG

        freeXorOffset = mMyCircuits[circuitIdx]->mCircuit.mGlobalOffset;

        memcpy(dest.data(), mMyCircuits[circuitIdx]->mCircuit.mOutputWires.data(), dest.size());
    }

    void Bucket::setGarbledInput(
        std::vector<u64>&& wireIdxs,
        std::vector<std::vector<block>>&& src)
    {
        mCopyInLabelIdxs = std::move(wireIdxs);
        mCopyInLabels = std::move(src);
    }



}
