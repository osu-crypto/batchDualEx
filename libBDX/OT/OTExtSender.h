#pragma once 
#include "OT/OTExtInterface.h"
#include "Common/BitVector.h"
#include "OT/BaseOT.h"

#include "Network/Channel.h"

#include <array>
#include <vector>
#ifdef GetMessage
#undef GetMessage
#endif
namespace libBDX {

	class OTExtSender :
		public I_OTExtSender
	{
	public: 

		//void Init(
		//	u64 numOTExt, 
		//	PRNG& prng,
		//	std::atomic<u64>& doneIdx) override;

		const block& GetMessage(u64 idx, const u8 choice) const override;



		void Extend(
			decltype(BaseOT::receiver_outputs)& base,
			decltype(BaseOT::receiver_inputs)& bits,
			u64 numOTExt, 
			PRNG& prng,
			Channel& chl,
			std::atomic<u64>& doneIdx) override;

	private:
		//void SendCorrelationValues(BaseOT& baseOTs, u64 numOTExt, PRNG& prng);
		//void eklundh_transpose128(std::vector<BitVector>& input, int offset);
		//void hash_outputs(BaseOT& baseOTs, u64 numOTExt);

		//void DebugCheck0(BaseOT& baseOTs);
		//void DebugCheck1(BaseOT& baseOTs, u64 numOTExt);
		//void DebugCheck2(BaseOT& baseOTs, u64 numOTExt);

		//Channel& mChannel;
		std::array<std::vector<block>, 2> mMessages;
	};
}

