#include "stdafx.h"
#include "CppUnitTest.h"

#include "Circuit_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace osuCryptoTests
{
	TEST_CLASS(Circuit_Tests)
	{
	public:


		TEST_METHOD(Circuit_BrisRead_SHA_Test)
		{
			InitDebugPrinting();
			Circuit_BrisRead_SHA_Test_Impl();
		}

		TEST_METHOD(Circuit_BrisRead_AES_Test)
		{
			InitDebugPrinting();
			Circuit_BrisRead_AES_Test_Impl();
		}

		TEST_METHOD(Circuit_Gen_Adder32_Test)
		{
			Circuit_Gen_Adder32_Test_Impl();
		}

		TEST_METHOD(Circuit_BrisRead_Adder32_Test)
		{
			Circuit_BrisRead_Adder32_Test_Impl();
		}


		//TEST_METHOD(DagCircuit_BrisRead_Adder32_Test)
		//{
		//	DagCircuit_BrisRead_Adder32_Test_Impl();
		//}

		//TEST_METHOD(DagCircuit_RandomReduce_Test)
		//{ 
		//	DagCircuit_RandomReduce_Test_Impl();
		//}
	};
}