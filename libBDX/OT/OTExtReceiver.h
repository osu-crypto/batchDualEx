#pragma once
#include "OT/OTExtInterface.h"
#include "OT/BaseOT.h"
#include "Network/Channel.h"
#include <vector>

#ifdef GetMessage
#undef GetMessage
#endif

namespace libBDX
{

	class OTExtReceiver :
		public I_OTExtReceiver
	{
	public:
		//OTExtReceiver(Channel& channel);
		//~OTExtReceiver();

		//void Init(u64 numOTExtPer, PRNG& prng, std::vector<std::atomic<u64>>& waits) override;
		 
		const block& GetMessage(u64 i) const override;

		void Extend(
			std::array< std::array<block, 2>, BASE_OT_COUNT>& baseOTs,
			u64 numOTExt, 
			PRNG& prng,
			Channel& chl,
			std::atomic<u64>& waits)override;

	private:

		//void CheckCorrelationValues(BaseOT& baseOTs, u64 numOTExt, PRNG& prng);
		

		//void DebugCheck0(BaseOT& baseOTs);
		//void DebugCheck1(BaseOT& baseOTs, u64 numOTExt);
		//void DebugCheck2(BaseOT& baseOTs, u64 numOTExt);
		//Channel& mChannel;
	public:
		std::vector<block> mMessages;
		//BitVector mChoiceBits;
	};

}
