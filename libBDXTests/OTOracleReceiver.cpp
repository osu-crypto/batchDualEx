#include "OTOracleReceiver.h"
#include "Common/Exceptions.h"

using namespace libBDX;


   OTOracleReceiver::OTOracleReceiver(OTOracleSender& sende, PRNG& prng, u64 numOTExt) 
   {
	   u64 bitSize = ((numOTExt + 127) / 128) * 128;

	   mChoiceBits.reserve(bitSize);
	   mChoiceBits.reset(numOTExt);
	   mMessages.resize(bitSize);

	   u64 size = (bitSize / 8) / sizeof(block);
	   block* data = (block*)mChoiceBits.data();


	   for (u64 i = 0; i < size; i++)
	   {
		   data[i] = prng.get_block(); 
	   }

	   for (u64 i = 0; i < mChoiceBits.size(); i++)
	   {
		   mMessages[i] = sende.GetMessage(i, mChoiceBits[i]);
	   }
   }


   OTOracleReceiver::~OTOracleReceiver()
   {
   }


   void OTOracleReceiver::Extend(
	   std::array< std::array<block, 2>, BASE_OT_COUNT> & baseOTs,
	   u64 numOTExt,
	   PRNG& prng,
	   Channel& chl,
	   std::atomic<u64>& waits)
   {
	   waits = numOTExt;
   }

   //bool OTOracleReceiver::GetChoice(u64 idx)
   //{
	  // return idx & 1;
   //}
   const block& OTOracleReceiver::GetMessage(u64 idx) const
   {
      return mMessages[idx];
   }
 
   //void OTOracleReceiver::Receive(const Index idx, const bool choice, OTMessage& result)
   //{
   //   if (mQueries.find(idx) != mQueries.end()) throw RepeatedOTException();
   //   mQueries.insert(idx);

   //   mSender.GetMessage(idx, choice, result); 
   //}

   //void OTOracleReceiver::Receive(const std::vector<Index>& idxs, const std::vector<bool>& choices, std::vector<OTMessage>& result)
   //{
   //   result.resize(idxs.size());
   //   for (u64 i = 0; i < idxs.size(); ++i)
   //      Receive(idxs[i], choices[i], result[i]);
   //}

   //void OTOracleReceiver::ReceiveRand(const Index idx, bool& randChoice, OTMessage& result)
   //{
   //   randChoice = (mSeedKey.mRoundKey[1].m128i_u64[0] * idx) & 64;
   //   Receive(idx, randChoice, result);
   //}

   //void OTOracleReceiver::ReceiveRand(const std::vector<Index>& idxs, std::vector<bool>& RandChoices, std::vector<OTMessage>& result)
   //{
   //   RandChoices.resize(idxs.size());
   //   result.resize(idxs.size());
   //   for (u64 i = 0; i < idxs.size(); ++i)
   //   {
   //      bool rand;
   //      ReceiveRand(idxs[i], rand, result[i]);
   //      RandChoices[i] = rand;
   //   }
   //}

   //void OTOracleReceiver::GetRandChoices(const std::vector<Index>& idxs, std::vector<bool>& RandChoices)
   //{
   //   throw not_implemented();
   //}
