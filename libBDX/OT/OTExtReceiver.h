#pragma once
//#include "OT/OTExtInterface.h"
//#include "OT/BaseOT.h"
#include "cryptoTools/Network/Channel.h"
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#ifdef GetMessage
#undef GetMessage
#endif

namespace osuCrypto
{

	class BDX_OTExtReceiver 
	{
	public:
		//BDX_OTExtReceiver(Channel& channel);
		//~BDX_OTExtReceiver();

		//void Init(u64 numOTExtPer, PRNG& prng, std::vector<std::atomic<u64>>& waits) override;
		 
		const block& GetMessage(u64 i) const;

		void Extend(
			std::array< std::array<block, 2>, 128>& baseOTs,
			u64 numOTExt, 
			PRNG& prng,
			Channel& chl,
			std::atomic<u64>& waits);

	private:

		//void CheckCorrelationValues(BaseOT& baseOTs, u64 numOTExt, PRNG& prng);
		

		//void DebugCheck0(BaseOT& baseOTs);
		//void DebugCheck1(BaseOT& baseOTs, u64 numOTExt);
		//void DebugCheck2(BaseOT& baseOTs, u64 numOTExt);
		//Channel& mChannel;
	public:
		std::vector<block> mMessages;
		BitVector mChoiceBits;
	};

}
