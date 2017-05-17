#include "stdafx.h"
#include "CppUnitTest.h"
#include "HalfGtGarbledCircuit_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace osuCryptoTests
{
   TEST_CLASS(HalfGtGarbledCircuit_Tests)
   {
   public:
      

	   TEST_METHOD(HalfGtGC_BasicGates_Test)
      {
		  InitDebugPrinting();
		  HalfGtGC_BasicGates_Test_Impl();
      }

      TEST_METHOD(HalfGtGC_BitAdder_Test)
      {
		  InitDebugPrinting();
		  HalfGtGC_BitAdder_Test_Impl();
      }

	  TEST_METHOD(HalfGtGC_BitAdder_Validate_Test)
	  {
		  InitDebugPrinting();
		  HalfGtGC_BitAdder_Validate_Test_Impl();
	  }

	  TEST_METHOD(HalfGtGC_AES_Test)
	  {
		  InitDebugPrinting();
		  HalfGtGC_AES_Test_Impl();
	  }
   };
}