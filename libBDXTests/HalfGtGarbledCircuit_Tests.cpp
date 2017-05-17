#include "HalfGtGarbledCircuit_Tests.h"

#include "Circuit/GarbledCircuit.h"
#include "Circuit/HalfGtGarbledCircuit.h"
#include "Circuit/Circuit.h"
//#include "MyAssert.h"
#include <fstream>
#include "Common.h"
#include <array>
#include "DebugCircuits.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Log.h"

using namespace osuCrypto;

void HalfGtGC_BasicGates_Test_Impl()
{
	block seed = _mm_set_epi32(4253465, 999999, 234435, 23987045);
	std::vector<bool> results;

	for (GateType gt : {GateType::Nor,
		GateType::nb_And,
		GateType::na_And,
		GateType::Xor,
		GateType::Nand,
		GateType::And,
		GateType::Nxor,
		GateType::nb_Or,
		GateType::na_Or,
		GateType::Or})
	{
		Circuit cd = OneGateCircuit(gt);


		std::vector<block> indexArray(10);
		for (u64 i = 0; i < indexArray.size(); ++i) indexArray[i] = _mm_set_epi64x(0, i);


		HalfGtGarbledCircuit gc;
		auto& logicTable = cd.Gates()[0];
#ifdef ADAPTIVE_SECURE
		std::vector<block> masks(cd.NonXorGateCount() * 2);
		PRNG prng(seed);
		prng.get((u8*)masks.data(), masks.size() * sizeof(block));

		std::vector<block> maskCopy = masks;
		//for (u64 i = 0; i < masks.size(); ++i)
		//{
		//	std::cout << masks[i] << " " << maskCopy[i] << std::endl;
		//}

		gc.Garble(cd, seed, indexArray, maskCopy);
#else 
		gc.Garble(cd, seed);
#endif
		BitVector out;
		std::vector<block> labels(3);

		for (u8 i = 0; i < 4; ++i)
		{
			block a = (i & 1) ? gc.mInputWires[0] ^ (gc.mGlobalOffset) : gc.mInputWires[0];
			block b = (i & 2) ? gc.mInputWires[1] ^ (gc.mGlobalOffset) : gc.mInputWires[1];

			labels[0] = (a);
			labels[1] = (b);

			gc.evaluate(cd, labels
#ifdef ADAPTIVE_SECURE
				, masks
#endif
				);
			gc.translate(cd, labels, out);

			u8 expected = logicTable.eval(i);
			results.push_back(expected == out[0]);

			if (results[i] == 0)
				throw UnitTestFail();
		}
	}
}


void ToBitVector(std::vector<bool>& vec, u64 input, u64 bits)
{
	for (u64 i = 0, mask = 1; i < bits; ++i, mask <<= 1)
	{
		vec.push_back((input & mask) != 0);
	}
}



void HalfGtGC_BitAdder_Test_Impl()
{
	u32 bits{ 4 };
	block seed = _mm_set_epi32(4253465, 3434565, 234435, 23987045);
	Circuit cd = AdderCircuit(bits);

	std::vector<block> indexArray(cd.WireCount());
	for (u64 i = 0; i < indexArray.size(); ++i) indexArray[i] = _mm_set_epi64x(0, i);

	HalfGtGarbledCircuit gc;
#ifdef ADAPTIVE_SECURE
	std::vector<block> masks(cd.NonXorGateCount() * 2);
	PRNG prng(seed);
	prng.get((u8*)masks.data(), masks.size() * sizeof(block));

	std::vector<block> maskCopy = masks;
	gc.Garble(cd, seed, indexArray, maskCopy);
#else 
	gc.Garble(cd, seed);
#endif
	for (u64 input0 = 0; input0 < (u64(1) << bits); ++input0)
	{
		for (u64 input1 = 0; input1 < (u64(1) << bits); ++input1)
		{
			std::vector<bool>inputVec;
			ToBitVector(inputVec, input0, bits);
			ToBitVector(inputVec, input1, bits);

			std::vector<block>labels(cd.WireCount());
			for (u64 i = 0; i < inputVec.size(); ++i)
			{
				if (inputVec[i])
					labels[i] = (gc.mInputWires[i] ^ (gc.mGlobalOffset));
				else
					labels[i] = (gc.mInputWires[i]);
			}

			gc.evaluate(cd, labels
#ifdef ADAPTIVE_SECURE
				, masks
#endif
				);
			BitVector outputVec;
			gc.translate(cd, labels, outputVec);

			std::vector<bool> expectedOut;
			ToBitVector(expectedOut, input0 + input1, bits + 1);

			//cd.Evaluate(inputVec);
			//std::vector<bool> outputVec2;
			//cd.Translate(inputVec, outputVec2);

			if (outputVec.size() != expectedOut.size())
				throw UnitTestFail();

			for (u64 i = 0; i < outputVec.size(); ++i)
			{
				if ((bool)outputVec[i] != (bool)expectedOut[i])
					throw UnitTestFail();

				//Assert::AreEqual(true, true, L"Output bits dont match");
			}
		}
	}
}



extern void swapEndian(BitVector& bv, u64 byteIdx);

void HalfGtGC_AES_Test_Impl()
{

	HalfGtGarbledCircuit gc;

	std::fstream in;
	std::string file = testData == "" ? "./circuits/AES-non-expanded.txt" : testData + "/circuits/AES-non-expanded.txt";

	in.open(file);

	if (in.is_open() == false)
		throw UnitTestFail("failed to open file: " + file);

	Circuit cd;
	cd.readBris(in, true);

	std::vector<block>indexArray(cd.WireCount());
	for (u64 i = 0; i < indexArray.size(); ++i)
		indexArray[i] = toBlock(i);
	block seed = toBlock(234234);

#ifdef ADAPTIVE_SECURE
	std::vector<block> masks(cd.NonXorGateCount() * 2);
	PRNG prng(seed);
	prng.get((u8*)masks.data(), masks.size() * sizeof(block));

	std::vector<block> maskCopy = masks;
	gc.Garble(cd, seed, indexArray, maskCopy);
#else 
	gc.Garble(cd, seed);
#endif



	BitVector inputVec(256);



	std::vector<block>labels(cd.WireCount());
	for (u64 i = 0; i < inputVec.size(); ++i)
	{
		if (inputVec[i])
			labels[i] = (gc.mInputWires[i] ^ (gc.mGlobalOffset));
		else
			labels[i] = (gc.mInputWires[i]);
	}
	gc.evaluate(cd, labels
#ifdef ADAPTIVE_SECURE
		, masks
#endif
	);
	BitVector output;
	gc.translate(cd, labels, output);


	block key = ZeroBlock;
	block data = ZeroBlock;
	block enc;

	AES keyShed(key);
	keyShed.ecbEncBlock(data, enc);

	BitVector expected;
	expected.assign(enc);

	for (int i = 0; i < 16; ++i)
	{
		swapEndian(output, i);
	}


	if (expected != output)
	{

		std::cout << "out  " << (output) << "  " << output.hammingWeight() << std::endl;
		std::cout << "outx " << (expected) << "  " << expected.hammingWeight() << std::endl;
		throw UnitTestFail();
	}
//	for (u64 input0 = 0; input0 < (u64(1) << bits); ++input0)
//	{
//		for (u64 input1 = 0; input1 < (u64(1) << bits); ++input1)
//		{
//			std::vector<bool>inputVec;
//			ToBitVector(inputVec, input0, bits);
//			ToBitVector(inputVec, input1, bits);
//
//			std::vector<block>labels(cd.WireCount());
//			for (u64 i = 0; i < inputVec.size(); ++i)
//			{
//				if (inputVec[i])
//					labels[i] = (gc.mInputWires[i] ^ (gc.mGlobalOffset));
//				else
//					labels[i] = (gc.mInputWires[i]);
//			}
//
//			gc.evaluate(cd, labels
//#ifdef ADAPTIVE_SECURE
//				, masks
//#endif
//			);
//			BitVector outputVec;
//			gc.translate(cd, labels, outputVec);
//
//			std::vector<bool> expectedOut;
//			ToBitVector(expectedOut, input0 + input1, bits + 1);
//
//			//cd.Evaluate(inputVec);
//			//std::vector<bool> outputVec2;
//			//cd.Translate(inputVec, outputVec2);
//
//			if (outputVec.size() != expectedOut.size())
//				throw UnitTestFail();
//
//			for (u64 i = 0; i < outputVec.size(); ++i)
//			{
//				if ((bool)outputVec[i] != (bool)expectedOut[i])
//					throw UnitTestFail();
//
//				//Assert::AreEqual(true, true, L"Output bits dont match");
//			}
//		}
//	}
}


void HalfGtGC_BitAdder_Validate_Test_Impl()
{
	u32 bits{ 4 };
	block seed = _mm_set_epi32(4253465, 3434565, 234435, 23987045);
	Circuit cd = AdderCircuit(bits);

	std::vector<block> indexArray(cd.WireCount());
	for (u64 i = 0; i < indexArray.size(); ++i) indexArray[i] = _mm_set_epi64x(0, i);
	HalfGtGarbledCircuit gc;
#ifdef ADAPTIVE_SECURE
	std::vector<block> masks(cd.NonXorGateCount() * 2);
	PRNG prng(seed);
	prng.get((u8*)masks.data(), masks.size() * sizeof(block));

	std::vector<block> maskCopy = masks;
	gc.Garble(cd, seed, indexArray, maskCopy);
#else 
	gc.Garble(cd, seed);
#endif

	gc.mGlobalOffset = ZeroBlock;
	gc.mInputWires.clear();
	gc.mOutputWires.clear();

	gc.Validate(cd, seed, indexArray
#ifdef ADAPTIVE_SECURE
		, masks
#endif
		);
}