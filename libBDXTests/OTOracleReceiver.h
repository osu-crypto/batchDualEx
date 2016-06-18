#pragma once
#include "OT/OTExtInterface.h"
#include <unordered_set>
#include "OTOracleSender.h"
#ifdef GetMessage
#undef GetMessage
#endif

using namespace libBDX;

class OTOracleReceiver :
	public I_OTExtReceiver
{
public:
	OTOracleReceiver(OTOracleSender& sender, PRNG& prng, u64 numOTExt);
	OTOracleReceiver() {}
	~OTOracleReceiver();

	void Extend(
		std::array< std::array<block, 2>, BASE_OT_COUNT> & baseOTs,
		u64 numOTExt,
		PRNG& prng,
		Channel& chl,
		std::atomic<u64>& waits) override;
	//bool GetChoice(u64 i) override;
	const block& GetMessage(u64 i) const override;

private:
	std::vector<block> mMessages;
	//block mSeed;
	//AES128::Key mSeedKey;
	//std::unordered_set<u64> mQueries;
	//OTOracleSender& mSender;
};
