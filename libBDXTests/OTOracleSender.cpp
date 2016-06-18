#include <unordered_map>
#include "Common/Defines.h"
#include "OTOracleSender.h"
#include <mutex>


using namespace libBDX;

OTOracleSender::OTOracleSender(PRNG& prng, u64 numOTExt)
{
	mMessages[0].resize(numOTExt);
	mMessages[1].resize(numOTExt);
	prng.get_u8s((u8*)mMessages[0].data(), numOTExt * sizeof(block));
	prng.get_u8s((u8*)mMessages[1].data(), numOTExt * sizeof(block));

}

OTOracleSender::~OTOracleSender()
{
}



void OTOracleSender::Extend(
	std::array<block, BASE_OT_COUNT>& base,
	BitVector& bits,
	u64 numOTExt,
	PRNG& prng,
	Channel& chl,
	std::atomic<u64>& doneIdx)
{


	doneIdx = numOTExt;
}

std::mutex mtx;

const block& OTOracleSender::GetMessage(u64 idx, const u8 choice) const
{
	return mMessages[choice][idx];
}

