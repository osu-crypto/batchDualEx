#include "stdafx.h"
#include "CppUnitTest.h"
#include <array>
#include "AES128_Tests.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libBDXTests
{

	TEST_CLASS(AES128_Tests)
	{
	public:
		TEST_METHOD(AES128_Enc_Test)
		{
			AES128_Enc_Test_Impl();
		}

		TEST_METHOD(AES128_Encblock4_Test)
		{
			AES128_Encblock4_Test_Impl();
		}

		TEST_METHOD(AES128_EncFewblocks_Test)
		{
			AES128_EncFewblocks_Test_Impl();
		}

		TEST_METHOD(AES128_EncManyblocks_Test)
		{
			AES128_EncManyblocks_Test_Impl();
		}
	};
}