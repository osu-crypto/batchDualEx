#include "stdafx.h"
#include "CppUnitTest.h"
#include "Common.h"
#include "CircuitPackage_Tests.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace osuCryptoTests
{

	TEST_CLASS(CircuitPackage_Tests)
	{
	public:


		TEST_METHOD(CircuitPackage_BitAdder_Test)
		{
			InitDebugPrinting("../test.out");
			CircuitPackage_BitAdder_Test_Impl();
		}
	};
}