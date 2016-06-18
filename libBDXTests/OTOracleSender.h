#pragma once
#include "OT/OTExtInterface.h"
#include "Common/Defines.h"
#include <unordered_map> 
#ifdef GetMessage
#undef GetMessage
#endif

using namespace libBDX;

class OTOracleSender :
	public I_OTExtSender
{
public:
	OTOracleSender(PRNG& prng, u64 numOTExt);
	~OTOracleSender();

	void Extend(
		std::array<block, BASE_OT_COUNT>& base,
		BitVector& bits,
		u64 numOTExt,
		PRNG& prng,
		Channel& chl,
		std::atomic<u64>& doneIdx)override;

	const block& GetMessage(u64 idx, const u8 choice) const override;
private:

	std::array<std::vector<block>, 2> mMessages;
	//mutable std::unordered_map<u64, block> mValues;
};
