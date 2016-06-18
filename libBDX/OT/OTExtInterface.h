#pragma once
#include "Common/Defines.h"
#include "Common/BitVector.h"
#include "Crypto/PRNG.h"
#include <future>
//#include <vector>


#ifdef GetMessage
#undef GetMessage
#endif
#define BASE_OT_COUNT 128

namespace libBDX
{
	class I_OTExtReceiver
	{
	public:
		I_OTExtReceiver() {}


		virtual void Extend(
			std::array< std::array<block, 2>, BASE_OT_COUNT> & baseOTs,
			u64 numOTExt,
			PRNG& prng,
			Channel& chl,
			std::atomic<u64>& waits)=0;

		virtual const block& GetMessage(u64 i) const = 0;
		 BitVector mChoiceBits;
	};

	class I_OTExtSender
	{
	public:
		I_OTExtSender() {}

		virtual void Extend(
			std::array<block, BASE_OT_COUNT>& base,
			BitVector& bits,
			u64 numOTExt,
			PRNG& prng,
			Channel& chl,
			std::atomic<u64>& doneIdx) = 0;

		//virtual void Init(u64 numOTExt, PRNG& prng, std::vector<std::atomic<u64>>& waits) = 0;
		virtual const block& GetMessage(u64 idx, const u8 choice) const = 0;
	};
}
