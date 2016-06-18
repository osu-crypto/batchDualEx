#include "stdafx.h"
#include "CppUnitTest.h"
#include "DualExActor_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace libBDXTests
{
	TEST_CLASS(DualExActor_Tests)
	{
	public:


		TEST_METHOD(DualExActor_BitAdder_Complete_Test)
		{
			InitDebugPrinting("../test.out");
			DualExActor_BitAdder_Complete_Test_Impl();
		}

		TEST_METHOD(DualExActor_BitAdder_Concurrent_Test)
		{
			InitDebugPrinting("../test.out");
			DualExActor_BitAdder_Concurrent_Test_Impl();
		}


		//TEST_METHOD(DualExActor_BitAdder_Init_Test)
		//{
		//	u64 numExe = 4,
		//		bucketSize = 4,
		//		numOpened = 8,
		//		psiSecParam = 40;

		//	Lg::setThreadName("DEA_Test_Thread_1");
		//	InitDebugPrinting("..\\test.out");

		//	Circuit c = AdderCircuit(4);
		//	NetworkManager netMgr0("127.0.0.1", 1212, 4, true);
		//	NetworkManager netMgr1("127.0.0.1", 1212, 4, false);

		//	OTOracleSender OTSend0;
		//	OTOracleReceiver OTRecv0(OTSend0);

		//	OTOracleSender OTSend1;
		//	OTOracleReceiver OTRecv1(OTSend1);

		//	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		//	PRNG prng1(prng0.get_block());

		//	DualExActor actor0(c, Role::First, numExe, bucketSize, numOpened, psiSecParam, netMgr0, OTRecv0, OTSend1);
		//	DualExActor actor1(c, Role::Second, numExe, bucketSize, numOpened, psiSecParam, netMgr1, OTRecv1, OTSend0);

		//	auto thrd = std::thread([&]() {
		//		Lg::setThreadName("DEA_Test_Thread_0");
		//		actor0.init(prng0);
		//	});

		//	actor1.init(prng1);

		//	thrd.join();

		//}




	};
}