#pragma once

#include <iostream>

//#define PUGIXML_HEADER_ONLY
//#include "pugixml-1.6\src\pugixml.hpp"
#include <vector>
#include "Wire.h"
#include "Gate.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto {

	class DagCircuit;

	class Circuit
	{
	public:
		friend class DagCircuit;

		Circuit();
		Circuit(std::array<u64, 2> inputs);
		~Circuit();

		//void readXML(std::istream& in);
		void readBris(std::istream& in, bool reduce = true);
		//void writeBris(std::ostream& out);

		void evaluate(BitVector& input);
		void translate(BitVector& labels, BitVector& output);

		void evaluate(std::vector<bool>& input);
		void translate(std::vector<bool>& labels, std::vector<bool>& output);

		void init();

		u64 AddGate(u64 input0, u64 input1, GateType gt);

		//inline void SetInputWireCount(Role role, u64 count)
		//{
		//   if(mInputWireCount != mWireCount )
		//      throw std::runtime_error("Input wires must be added first");

		//   // in case they had already set the input count
		//   mInputWireCount -= mInputs[role];
		//   mWireCount -= mInputs[role]; 

		//   // add the new wire count
		//   mInputWireCount += count;
		//   mWireCount += count;

		//   mInputs[role] = count;
		//}

		inline void AddOutputWire(u64 i, bool invert)
		{
			if (i >= mWireCount)
				throw std::runtime_error("");
			mOutputs.push_back(i);
            mOutputInverts.push_back(invert);
		}

		inline const u64 InputWireCount() const
		{
			return mInputs[0] + mInputs[1];
		}
		inline const u64& WireCount()const
		{
			return mWireCount;
		}
		inline const u64& NonXorGateCount()const
		{
			return mNonXorGateCount;
		}
		inline u64 OutputCount()const
		{
            return mOutputs.size();
		}

		inline const std::array<u64, 2>& Inputs() const
		{
			return mInputs;
		}
		inline const  std::vector<Gate>& Gates() const
		{
			return mGates;
		}
		inline const std::vector<u64>& Outputs() const
		{
			return mOutputs;
		}
		
		void xorShareInputs();

        std::vector<u8> mOutputInverts;

		//std::vector<block> mIndexArray;
	private:

		
		//void ParseXMLInputs(pugi::xml_node& inputs);
		//void ParseXMLGates(pugi::xml_node& gates);
		//void ParseXMLOutput(pugi::xml_node& outputs);

		u64 mWireCount, mNonXorGateCount;
		std::array<u64, 2> mInputs;
		std::vector<Gate> mGates;
		std::vector<u64> mOutputs;
	};

}
