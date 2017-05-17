#include "Circuit.h"
#include "Gate.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Exceptions.h"
#include <sstream>
#include <unordered_map>
#include <set>



namespace osuCrypto {



	Circuit::Circuit()
	{
		mWireCount = mNonXorGateCount = 0;
	}
	Circuit::Circuit(std::array<u64, 2> inputs)
		: mInputs(inputs)
	{
		mWireCount = mInputs[0] + mInputs[1];
		mNonXorGateCount = 0;

		//mIndexArray.resize(InputWireCount());
		//for (u64 i = 0; i < InputWireCount(); ++i)
		//{
		//	mIndexArray[i] = _mm_set_epi64x(0, i);
		//}
	}


	Circuit::~Circuit()
	{
	}


	//void Circuit::init()
	//{

	//    //mIndexArray.resize(std::max(WireCount(), NonXorGateCount() * 2));
	//    //for (u64 i = 0; i < mIndexArray.size(); ++i)
	//    //{
	//    //	mIndexArray[i] = _mm_set1_epi64x(i);
	//    //}
	//}



	u64 Circuit::AddGate(u64 input0, u64 input1, GateType gt)
	{
		if (input0 > mWireCount)
			throw std::runtime_error("input wire " + std::to_string(input0) + " not defined. " + LOCATION);
		if (input1 > mWireCount && (gt != GateType::na || input1 != (u64)-1))
			throw std::runtime_error("input wire " + std::to_string(input1) + " not defined. " + LOCATION);

		if (gt == GateType::a ||
			gt == GateType::b ||
			gt == GateType::nb ||
			gt == GateType::One ||
			gt == GateType::Zero)
			throw std::runtime_error("");

		if (gt != GateType::Xor && gt != GateType::Nxor) ++mNonXorGateCount;
		mGates.emplace_back(input0, input1, mWireCount, gt);
		return mWireCount++;
	}

	void Circuit::readBris(std::istream & in, bool reduce)
	{
		if (in.eof())
			throw std::runtime_error("Circuit::readBris input istream is emprty");



		u64 numGates; in >> numGates;
		u64 numWires; in >> numWires;

		u64 p0InCount; in >> p0InCount;
		u64 p1InCount; in >> p1InCount;
		u64 outCount; in >> outCount;


		mInputs[0] = p0InCount;
		mInputs[1] = p1InCount;
		//mWireCount = numWires;
		mNonXorGateCount = 0;
		mOutputs.resize(outCount, -1);
		mOutputInverts.resize(outCount);

		std::vector<WireNode>& nodes = mNodes;
		nodes.resize(0);
		nodes.resize(numWires);

		std::vector<u64> wireToGateMap(numWires, -1), oldToNewWireMap(numWires, -1);
		mNewToOldWireMap.resize(numWires, -1);

		u64 nextWireIdx = InputWireCount();
		mGates.reserve(numWires - InputWireCount());

		for (u64 i = 0; i < p0InCount + p1InCount; ++i)
		{
			nodes[i].outWireId = i;
			wireToGateMap[i] = i;
			oldToNewWireMap[i] = i;
			mNewToOldWireMap[i] = i;
		}

		if (!reduce)
		{
			for (u64 i = numWires - mOutputs.size(), j =0; i < numWires; ++i, ++j)
			{
				mOutputs[j] = i;
			}
		}


		u64 fanIn, fanOut, in0, in1, out;
		std::string typeStr;


		for (u64 i = p0InCount + p1InCount; i < numWires; ++i)
		{
			in >> fanIn >> fanOut;

			if (fanIn == 1)
			{
				in >> in0 >> out >> typeStr;
				if (typeStr != "INV")
				{
					std::cout << "only INV gates are supported with fan in 1." << std::endl;
					throw std::runtime_error(LOCATION);
				}


				nodes[i].mType = GateType::na;
				nodes[i].inputs[0] = in0;
				nodes[i].outWireId = out;
				wireToGateMap[out] = i;


				if (reduce)
				{
					if (out >= numWires - mOutputInverts.size())
					{
						// if we want to remove INV gates, but have one on the output, we 
						// simply "eliminate" the INV gate and make this output as needing
						// to be inverted by the external code. Most of the complexity here
						// is to then support   ... -> INV -> INV -> output
						auto outPosition = out + mOutputs.size() - numWires;

						bool inv = true;


						// first get the input node to this gate. 
						auto inputNodeIdx = wireToGateMap[nodes[i].inputs[0]];

						// if this input node is also an INV gate, continue to 
						// follow the inputs until we get a non INV gate. At each depth,
						// toggle whether we need to invert the output.
						while (nodes[inputNodeIdx].mType == GateType::na)
						{
							inputNodeIdx = wireToGateMap[nodes[inputNodeIdx].inputs[0]];
							inv = !inv;
						}

						// We found a non-INV gate. It has output Wire idx inputWireIdx
						auto inputWireIdx = nodes[inputNodeIdx].outWireId;
						// This denotes whether we need to INV (odd number of INV gate)
						mOutputInverts[outPosition] = inv;

						// some error checking
						if (mOutputs[outPosition] != -1)
							throw std::runtime_error(LOCATION);

						// Since we are reducing, its no longer true that the last n wires
						// are the output. Lets keep track of which one this is.
						mOutputs[outPosition] = oldToNewWireMap[inputWireIdx];

						//std::cout << "outP " << outPosition << std::endl;
					}
				}
				else
				{
					mGates.emplace_back(in0, -1, out, GateType::na);
				}
			}
			else
			{
				in >> in0 >> in1 >> out >> typeStr;

				if (typeStr != "AND" && typeStr != "XOR")
				{
					std::cout << "only AND, XOR gates are supported with fan in 2." << std::endl;
					throw std::runtime_error(LOCATION);
				}

				nodes[i].mType = typeStr == "AND" ? GateType::And : GateType::Xor;
				nodes[i].outWireId = out;
				nodes[i].inputs[0] = in0;
				nodes[i].inputs[1] = in1;
				wireToGateMap[out] = i;

				if (nodes[i].mType == GateType::And)
					++mNonXorGateCount;

				if (out == numWires)
				{
					throw std::runtime_error("circuit files with 1 indexing are not allowed.\n" LOCATION);
				}


				GateType type = nodes[i].mType;


				if (reduce)
				{
					auto input0gateIdx = wireToGateMap[nodes[i].inputs[0]];
					auto input1gateIdx = wireToGateMap[nodes[i].inputs[1]];


					if (nodes[input0gateIdx].mType == GateType::na)
					{
						// absorb in the invert gate.
						type = invertInputWire(0, type);

						// now take the invert gate's input directly
						in0 = nodes[input0gateIdx].inputs[0];

						// make sure there isnt another inver gate behind the one just eliminated.
						if (nodes[wireToGateMap[in0]].mType == GateType::na)
							throw std::runtime_error("double invert " LOCATION);
					}

					if (nodes[input1gateIdx].mType == GateType::na)
					{
						// absorb in the invert gate.
						type = invertInputWire(1, type);
						// now take the invert gate's input directly
						in1 = nodes[input1gateIdx].inputs[0];

						// make sure there isnt another inver gate behind the one just eliminated.
						if (nodes[wireToGateMap[in1]].mType == GateType::na)
							throw std::runtime_error("double invert " LOCATION);
					}


					if (out >= numWires - mOutputInverts.size())
					{
						auto outPosition = out + mOutputs.size() - numWires;

						if (mOutputs[outPosition] != -1)
							throw std::runtime_error(LOCATION);

						mOutputs[outPosition] = nextWireIdx;
						mOutputInverts[outPosition] = 0;
					}


					mNewToOldWireMap[nextWireIdx] = out;
					oldToNewWireMap[out] = nextWireIdx;
					out = nextWireIdx++;

					in0 = oldToNewWireMap[in0];
					in1 = oldToNewWireMap[in1];
				}


				mGates.emplace_back(in0, in1, out, type);


			}
		}

		mWireCount = InputWireCount() + mGates.size();
	}

	//void Circuit::readBris(std::istream & in, bool reduce)
	//{
	//	if (in.eof())
	//		throw std::runtime_error("Circuit::readBris input istream is emprty");




	//	//BetaCircuit c;

	//	u64 numGates; in >> numGates;
	//	u64 numWires; in >> numWires;

	//	u64 p0InCount; in >> p0InCount;
	//	u64 p1InCount; in >> p1InCount;
	//	u64 outCount; in >> outCount;

	//	//mOutputs.resize(outCount);
	//	//mOutputInverts.resize(outCount);
	//	BitVector initialized(numWires), invertFlags(numWires);
	//	std::vector<u64> defMap(numWires, -1), newIdxs(numWires, -1);

	//	//std::vector<BetaWire> wires(numWires);

	//	//BetaBundle 
	//	//    in0Wires(p0InCount), 
	//	//    in1Wires(p1InCount), 
	//	//    temp(numWires - p0InCount - p1InCount);

	//	//c.addInputBundle(in0Wires);
	//	//c.addInputBundle(in1Wires);
	//	//c.addTempWireBundle(temp);


	//	mInputs[0] = p0InCount;
	//	mInputs[1] = p1InCount;
	//	mWireCount = p0InCount + p1InCount;

	//	for (u64 i = 0; i < p0InCount + p1InCount; ++i)
	//	{
	//		newIdxs[i] = i;
	//		initialized[i] = 1;
	//	}

	//	u64 fanIn, fanOut, in0, in1, out;
	//	std::string type;


	//	for (u64 i = 0; i < numGates; ++i)
	//	{
	//		in >> fanIn >> fanOut;

	//		if (fanIn == 1)
	//		{
	//			in >> in0 >> out >> type;
	//			if (type != "INV")
	//			{
	//				std::cout << "only INV gates are supported with fan in 1." << std::endl;
	//				throw std::runtime_error(LOCATION);
	//			}

	//			if (initialized[in0] == false)
	//			{
	//				std::cout << "uninitialized wire used " << in0 << ". Input must be topological" << std::endl;
	//				throw std::runtime_error(LOCATION);
	//			}

	//			invertFlags[out] = 1;
	//			defMap[out] = in0;

	//			if (out >= numWires - outCount)
	//			{
	//				AddOutputWire(newIdxs[in0], true);
	//			}
	//		}
	//		else
	//		{
	//			in >> in0 >> in1 >> out >> type;

	//			if (type != "AND" && type != "XOR")
	//			{
	//				std::cout << "only AND, XOR gates are supported with fan in 2." << std::endl;
	//				throw std::runtime_error(LOCATION);
	//			}

	//			if (initialized[in0] == false)
	//			{
	//				std::cout << "uninitialized wire used " << in0 << ". Input must be topological" << std::endl;
	//				throw std::runtime_error(LOCATION);
	//			}

	//			if (initialized[in1] == false)
	//			{
	//				std::cout << "uninitialized wire used " << in1 << ". Input must be topological" << std::endl;
	//				throw std::runtime_error(LOCATION);
	//			}

	//			auto gt = type == "AND" ? GateType::And : GateType::Xor;


	//			u8 invert = 0;
	//			while (invertFlags[in0])
	//			{
	//				in0 = defMap[in0];
	//				invert ^= 1;
	//			}

	//			if (invert)
	//			{
	//				gt = invertInputWire(0, gt);
	//			}

	//			invert = 0;
	//			while (invertFlags[in1])
	//			{
	//				in1 = defMap[in1];
	//				invert ^= 1;
	//			}

	//			if (invert)
	//			{
	//				gt = invertInputWire(1, gt);
	//			}


	//			in0 = newIdxs[in0];
	//			in1 = newIdxs[in1];

	//			newIdxs[out] = AddGate(in0, in1, gt);

	//			if (out >= numWires - outCount)
	//			{
	//				AddOutputWire(newIdxs[out], false);
	//				//mOutputs[out + outCount - numWires] = newIdxs[out];
	//			}

	//		}

	//		initialized[out] = 1;
	//	}



	//	//for (u64 i = 0; i < c.mGates.size(); ++i)
	//	//{
	//	//    switch (c.mGates[i].mType)
	//	//    {
	//	//    case GateType::Nor:
	//	//    case GateType::nb_And:
	//	//    case GateType::na_And :
	//	//    case GateType::Xor:
	//	//    case GateType::Nand:
	//	//    case GateType::And:
	//	//    case GateType::Nxor:
	//	//    case GateType::nb_Or:
	//	//    case GateType::na_Or:
	//	//    case GateType::Or:
	//	//    {

	//	//        auto gt = c.mGates[i].mType;
	//	//        in0 = c.mGates[i].mInput[0];
	//	//        in1 = c.mGates[i].mInput[1];

	//	//        if (in0 > p0InCount + p1InCount)
	//	//        {
	//	//            if (c.isInvert(in0))
	//	//            {
	//	//                gt = invertInputWire(0, gt);
	//	//            }
	//	//            if (c.isInvert(in0) || mGates[defMap[in0]].Type() == GateType::a)
	//	//            {
	//	//                in0 = mGates[defMap[in0]].mInput[0];
	//	//            }
	//	//        }
	//	//        if (in1 > p0InCount + p1InCount)
	//	//        {
	//	//            if (c.isInvert(in1))
	//	//            {
	//	//                gt = invertInputWire(1, gt);
	//	//            }
	//	//            if (c.isInvert(in1) || mGates[defMap[in1]].Type() == GateType::a)
	//	//                in1 = mGates[defMap[in1]].mInput[0];
	//	//        }

	//	//        c.mGates[i].mOutput = AddGate(
	//	//            in0,
	//	//            in1,
	//	//            gt);

	//	//        defMap[c.mGates[i].mOutput] = i;

	//	//        break;
	//	//    }
	//	//    case GateType::a:
	//	//    case GateType::na:
	//	//        defMap[c.mGates[i].mOutput] = i;
	//	//        break;
	//	//    case GateType::nb:
	//	//    case GateType::b:
	//	//    case GateType::Zero:
	//	//    case GateType::One:
	//	//    default:
	//	//        throw std::runtime_error(LOCATION);
	//	//        break;
	//	//    }

	//	//    //AddGate()
	//	//}


	//	//DagCircuit dag;
	//	//dag.readBris(in);

	//	//if (reduce)
	//	//	dag.removeInvertGates();

	//	//dag.toCircuit(*this);

	//	//if (reduce)
	//	//{
	//	//	if (mGates.size() != dag.mNonInvertGateCount)
	//	//		throw std::runtime_error("");
	//	//}
	//	//else
	//	//{
	//	//	if (mGates.size() != dag.mGates.size())
	//	//		throw std::runtime_error("");
	//	//}

	//	//init();
	//	//if (reduce)
	//	//{
	//	//	// remove all invert gates by absorbing them into the downstream logic tables
	//	//	for (auto gate : invGates)
	//	//	{
	//	//		gate->reduceInvert(numGates);
	//	//	}
	//	//}

	//	//// now we have a DAG of non invert gates. 
	//	//for (u64 i = 0; i < InputWireCount(); ++i)
	//	//{
	//	//	// recursively add the child gates in topo order
	//	//	for (auto child : gateNodes[i].mChildren)
	//	//		child->add(*this);
	//	//}

	//	//for (auto output : outputs)
	//	//{
	//	//	AddOutputWire(output.mGate->mOutWireIdx);
	//	//}

	//	//if (mOutputs.size() != outputCount)
	//	//	throw std::runtime_error("");

	//	//if (mGates.size() != numGates)
	//	//	throw std::runtime_error("not all gates were added, maybe there is a cycle or island in the dag...");
	//}



	void Circuit::evaluate(std::vector<bool>& labels)
	{
		BitVector bb(labels.size());
		for (u64 i = 0; i < labels.size(); ++i)
			bb[i] = labels[i];

		evaluate(bb);

		for (u64 i = 0; i < labels.size(); ++i)
			labels[i] = bb[i];
	}

	void Circuit::translate(std::vector<bool>& labels, std::vector<bool>& output)
	{
		BitVector bb(labels.size()), oo;
		for (u64 i = 0; i < labels.size(); ++i)
			bb[i] = labels[i];

		translate(bb, oo);

		for (u64 i = 0; i < oo.size(); ++i)
			output[i] = oo[i];
	}
	void __swapEndian(BitVector& bv, u64 byteIdx)
	{
		BitVector bb;

		bb.copy(bv, byteIdx * 8, 8);

		for (u64 i = 0; i < 8; ++i)
		{
			bv[byteIdx * 8 + i] = bb[7 - i];
		}
	}



	void Circuit::evaluate(BitVector& labels)
	{

		//BitVector __labels = labels; 
		//__labels.resize(mWireCount);


		//for (u64 i = InputWireCount(); i < mWireCount; ++i)
		//{
		//	if (mNodes[i].mType == GateType::na)
		//	{
		//		__labels[mNodes[i].outWireId] = !__labels[mNodes[i].inputs[0]];
		//	}
		//	else  if(mNodes[i].mType == GateType::And)
		//	{
		//		__labels[mNodes[i].outWireId] = __labels[mNodes[i].inputs[0]] && __labels[mNodes[i].inputs[1]];
		//	}
		//	else if (mNodes[i].mType == GateType::Xor)
		//	{
		//		__labels[mNodes[i].outWireId] = __labels[mNodes[i].inputs[0]] ^ __labels[mNodes[i].inputs[1]];
		//	}
		//	else
		//	{
		//		throw std::runtime_error(LOCATION);
		//	}
		//}

		//return;

		labels.resize(mWireCount);


		for (u64 i = 0; i < mGates.size(); ++i)
		{
			if (mGates[i].Type() == GateType::na)
			{
				labels[mGates[i].mOutput] = !labels[mGates[i].mInput[0]];
			}
			else
			{
				u8 a = labels[mGates[i].mInput[0]] ? 1 : 0;
				u8 b = labels[mGates[i].mInput[1]] ? 2 : 0;
				labels[mGates[i].mOutput] = mGates[i].eval(a | b);
			}

			//if (labels[mGates[i].mOutput] != __labels[mNewToOldWireMap[mGates[i].mOutput]])
			//{
			//	std::cout << "bad @ new "<< mGates[i].mOutput << "   old "<< mNewToOldWireMap[mGates[i].mOutput] << std::endl;
			//}

			//if (mOutputs[94] == mGates[i].mOutput)
			//{
			//	std::cout << "bit  94 " << labels[mGates[i].mOutput] << " vs "<<  __labels[mNewToOldWireMap[mGates[i].mOutput]] <<"  old wire idx " << mNewToOldWireMap[mGates[i].mOutput] << " exp " << mWireCount - 256 + 94 << std::endl;
			//}
		}

		//BitVector bb;
		//bb.copy(__labels, __labels.size() - 256, 256);

		//for (u64 i = 0; i < 32; ++i)
		//{
		//	//__swapEndian(bb, i);
		//}

		//std::cout << "bb " << bb << std::endl;
	}

	void Circuit::translate(BitVector& labels, BitVector& output)
	{

		output.reset(mOutputs.size());
		for (u64 i = 0; i < mOutputs.size(); i++)
		{
			//std::cout << i << "  " << mOutputs[i] << std::endl;
			auto& wireIdx = mOutputs[i];
			output[i] = labels[wireIdx] ^ mOutputInverts[i];
		}
	}



	void Circuit::xorShareInputs()
	{

		u64 wiresAdded = mInputs[0] + mInputs[1];

		std::array<u64, 2> oldInputs = mInputs;
		std::vector<Gate> oldGates(std::move(mGates));

		mInputs[0] += mInputs[1];
		mInputs[1] = mInputs[0];


		u64 inIter0 = 0;
		u64 inIter1 = mInputs[0];
		u64 outIter = mInputs[0] + mInputs[1];

		mGates.reserve(oldGates.size() + wiresAdded);

		for (u64 i = 0; i < oldInputs[0]; ++i)
		{
			mGates.emplace_back(inIter0++, inIter1++, outIter++, GateType::Xor);
		}

		for (u64 i = 0; i < oldInputs[1]; ++i)
		{
			mGates.emplace_back(inIter0++, inIter1++, outIter++, GateType::Xor);
		}

		u64 offset = 2 * wiresAdded;
		mWireCount = mWireCount + offset;

		for (auto& gate : oldGates)
		{
			mGates.emplace_back(
				gate.mInput[0] + offset,
				gate.mInput[1] + offset,
				gate.mOutput + offset,
				gate.Type());
		}

		for (auto& output : mOutputs)
			output += offset;
	}
}