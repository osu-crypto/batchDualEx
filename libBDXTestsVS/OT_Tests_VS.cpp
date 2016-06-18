#include "stdafx.h"
#include "CppUnitTest.h"
#include "OT_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libBDXTests
{
	TEST_CLASS(OT_Tests)
	{
	public:


		TEST_METHOD(BitVector_Indexing_Test)
		{
			BitVector_Indexing_Test_Impl();
		}

		TEST_METHOD(BitVector_Parity_Test)
		{
			BitVector_Parity_Test_Impl();
		}

		TEST_METHOD(BitVector_Append_Test)
		{
			BitVector_Append_Test_Impl();
		}

		TEST_METHOD(BitVector_Copy_Test)
		{
			BitVector_Copy_Test_Impl();
		}

		TEST_METHOD(OTExt_100Receive_Test)
		{
			InitDebugPrinting("../test.out");
			OTExt_100Receive_Test_Impl();
		}

		TEST_METHOD(Transpose_Test)
		{
			InitDebugPrinting("../test.out");
			Transpose_Test_Impl();
		}
	};
}