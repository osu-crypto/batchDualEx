#include "stdafx.h"
#include "CppUnitTest.h"
#include "PSI_Tests.h"
#include "AsyncPSI_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libBDXTests
{
	TEST_CLASS(PSI_Tests)
	{
	public:

		TEST_METHOD(PSI_EmptrySet_Test)
		{
			Psi_EmptrySet_Test_Impl();
		}

		TEST_METHOD(PSI_FullSet_Test)
		{
			InitDebugPrinting("..\\test.out");
			Psi_FullSet_Test_Impl();
		}

		TEST_METHOD(PSI_SingltonSet_Test)
		{
			InitDebugPrinting("..\\test.out");
			Psi_SingltonSet_Test_Impl();
		}
		
		TEST_METHOD(PSI_SingltonSet_Serial_Test)
		{
			InitDebugPrinting("..\\test.out");
			Psi_SingltonSet_Serial_Test_Impl();
		}
		TEST_METHOD(AsyncPsi_EmptrySet_Test)
		{
			AsyncPsi_EmptrySet_Test_Impl();
		}

		TEST_METHOD(AsyncPsi_FullSet_Test)
		{
			InitDebugPrinting("..\\test.out");
			AsyncPsi_FullSet_Test_Impl();
		}

		TEST_METHOD(AsyncPsi_SingltonSet_Test)
		{
			InitDebugPrinting("..\\test.out");
			AsyncPsi_SingltonSet_Test_Impl();
		}
	};
}