#include "AES128_Tests.h"

#include "Common/Defines.h"
#include "Crypto/AES.h"
#include "Circuit/Gate.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
//#include "MyAssert.h"
#include "Common.h"

using namespace libBDX;

void AES128_Enc_Test_Impl()
{
	//TestContext tc("AES128_Tests");

	//for (TestData td : tc.TestData("AES128_Enc_Test"))
	//   ts.Get("Threads", i);

	block userKey = _mm_set_epi64x(3801686154756598164, 7886001212563314667);
	block src = _mm_set_epi64x(-6202265095379581698, -3495722710746186735);

	for (u32 i = 0; i < 1; ++i)
	{

		AES128::Key keySched;
		AES128::EncKeyGen(userKey, keySched);

		CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc(ByteArray(userKey), sizeof(userKey));

		block expected = ZeroBlock;

		enc.ProcessData(ByteArray(expected), ByteArray(src), sizeof(src));

		block actual;
		AES128::EcbEncBlock(keySched, src, actual);

		if (notEqual(expected, actual))
			throw UnitTestFail();


		AES128::Key decKeySched;
		AES128::DecKeyGen(userKey, decKeySched);
		AES128::EcbDecBlock(decKeySched, actual, actual);

		if (notEqual(src, actual))
			throw UnitTestFail();

		userKey = src;
		src = expected;
	}
}


void AES128_Encblock4_Test_Impl()
{
	block userKey = _mm_set_epi32(4253465, 3434565, 234435, 23987045);

	AES128::Key keySched;
	AES128::EncKeyGen(userKey, keySched);

	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc(ByteArray(userKey), sizeof(userKey));

	std::array<block, 4> src
	{ {
			_mm_set1_epi64x(124354325422),
			_mm_set1_epi64x(678978945678),
		_mm_set1_epi64x(4658245695657),
		_mm_set1_epi64x(245743567809)
		} };

	std::array<block, 4> expected;

	enc.ProcessData(ByteArray(expected[0]), ByteArray(src[0]), sizeof(src));

	std::array<block, 4> actual;
	AES128::EcbEncFourBlocks(keySched, src.data(), actual.data());

	if(notEqual(expected[0], actual[0])) throw UnitTestFail();
	if(notEqual(expected[1], actual[1])) throw UnitTestFail();
	if(notEqual(expected[2], actual[2])) throw UnitTestFail();
	if(notEqual(expected[3], actual[3])) throw UnitTestFail();


	AES128::Key decKeySched;
	AES128::DecKeyGen(userKey, decKeySched);
	AES128::EcbDecBlock(decKeySched, actual[0], actual[0]);
	AES128::EcbDecBlock(decKeySched, actual[1], actual[1]);
	AES128::EcbDecBlock(decKeySched, actual[2], actual[2]);
	AES128::EcbDecBlock(decKeySched, actual[3], actual[3]);


	if(notEqual(src[0], actual[0])) throw UnitTestFail();
	if(notEqual(src[1], actual[1])) throw UnitTestFail();
	if(notEqual(src[2], actual[2])) throw UnitTestFail();
	if(notEqual(src[3], actual[3])) throw UnitTestFail();
}

void AES128_EncFewblocks_Test_Impl()
{
	 
	block userKey = _mm_set_epi32(4253465, 3434565, 234435, 23987045);

	AES128::Key keySched;
	AES128::EncKeyGen(userKey, keySched);

	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc(ByteArray(userKey), sizeof(userKey));

	std::vector<block> src
	{ {
			_mm_set1_epi64x(124354325422),
			_mm_set1_epi64x(678978945678),
		_mm_set1_epi64x(4658245695657),
		_mm_set1_epi64x(245743567809)
		} };

	std::vector<block> expected(4);
	enc.ProcessData(ByteArray(expected[0]), ByteArray(src[0]), sizeof(block) * src.size());

	std::vector<block> actual(4);
	AES128::EcbEncBlocks(keySched, src.data(), actual.data(), src.size());

	if(notEqual(expected[0], actual[0])) throw UnitTestFail();
	if(notEqual(expected[1], actual[1])) throw UnitTestFail();
	if(notEqual(expected[2], actual[2])) throw UnitTestFail();
	if(notEqual(expected[3], actual[3])) throw UnitTestFail();

	AES128::Key decKeySched;
	AES128::DecKeyGen(userKey, decKeySched);
	AES128::EcbDecBlock(decKeySched, actual[0], actual[0]);
	AES128::EcbDecBlock(decKeySched, actual[1], actual[1]);
	AES128::EcbDecBlock(decKeySched, actual[2], actual[2]);
	AES128::EcbDecBlock(decKeySched, actual[3], actual[3]);


	if(notEqual(src[0], actual[0])) throw UnitTestFail();
	if(notEqual(src[1], actual[1])) throw UnitTestFail();
	if(notEqual(src[2], actual[2])) throw UnitTestFail();
	if(notEqual(src[3], actual[3])) throw UnitTestFail();
}


void AES128_EncManyblocks_Test_Impl()
{
	const u64 blockCount = 123; 
	block userKey = _mm_set_epi32(4253465, 3434565, 234435, 23987045);

	AES128::Key keySched;
	AES128::EncKeyGen(userKey, keySched);

	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc(ByteArray(userKey), sizeof(userKey));

	std::vector<block> src(blockCount);
	for (u64 i = 0; i < blockCount; ++i)
		src[i] = _mm_set_epi64x(i, i);

	std::vector<block> expected(blockCount);
	enc.ProcessData(ByteArray(expected[0]), ByteArray(src[0]), sizeof(block) * src.size());

	std::vector<block> actual(blockCount);
	AES128::EcbEncBlocks(keySched, src.data(), actual.data(), src.size());

	for (u64 i = 0; i < blockCount; ++i)
		if (notEqual(expected[i], actual[i]))
			throw UnitTestFail();

	AES128::Key decKeySched;
	AES128::DecKeyGen(userKey, decKeySched);

	for (u64 i = 0; i < blockCount; ++i)
		AES128::EcbDecBlock(decKeySched, actual[i], actual[i]);

	for (u64 i = 0; i < blockCount; ++i)
		if(notEqual(src[i], actual[i]))
			throw UnitTestFail();
}
