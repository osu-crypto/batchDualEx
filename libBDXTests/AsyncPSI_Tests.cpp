#include "AsyncPSI_Tests.h"

#include "Common.h"
#include "cryptoTools/Common/Defines.h"
#include "PSI/AsyncPsiReceiver.h"
#include "PSI/AsyncPsiSender.h"
#include "cryptoTools/Network/BtEndpoint.h"
#include "cryptoTools/Common/Log.h"
//
//#include "cryptoTools/Cryptopp/aes.h"
//#include "cryptoTools/Cryptopp/modes.h"
//#include "MyAssert.h"
#include "cryptoTools/Common/Timer.h"
#include <array>

using namespace osuCrypto;





void AsyncPsi_EmptrySet_Test_Impl()
{
	u64 repeatCount = 3;
	u64 setSize = 10, psiSecParam = 40;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = prng.get<block>();
		recvSet[i] = prng.get<block>();
	}

	std::string name("psi");

	BtIOService ios(0);
	BtEndpoint ep0(ios, "localhost", 1212, true, name);
	BtEndpoint ep1(ios, "localhost", 1212, false, name);
	std::vector<Channel*> sendChls(setSize),recvChls(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		recvChls[i] = &ep1.addChannel(name + std::to_string(i), name + std::to_string(i));
		sendChls[i] = &ep0.addChannel(name + std::to_string(i), name + std::to_string(i));
	}

	//OTOracleSender OTSender(prng, AsyncPsiSender::PsiOTCount(setSize, psiSecParam) * repeatCount);
	//OTOracleReceiver OTRecver(OTSender, prng, AsyncPsiReceiver::PsiOTCount(setSize, psiSecParam)*repeatCount);


    BDX_OTExtReceiver OTRecver;
    BDX_OTExtSender OTSender;
    {
        std::atomic<u64> _1(0), _2(0);
        std::array<block, 128> baseRecvMsg;
        BitVector baseRecvChoice(128); baseRecvChoice.randomize(prng);
        std::array<std::array<block, 2>, 128>baseSendMsg;
        prng.get(baseSendMsg.data(), baseSendMsg.size());
        for (u64 i = 0; i < 128; ++i)
        {
            baseRecvMsg[i] = baseSendMsg[i][baseRecvChoice[i]];
        }
        u64 numOTs = AsyncPsiSender::PsiOTCount(setSize, psiSecParam) * repeatCount;
        auto thrd = std::thread([&]() {OTRecver.Extend(baseSendMsg, numOTs, prng, *recvChls[0], _1); });
        OTSender.Extend(baseRecvMsg, baseRecvChoice, numOTs, prng, *sendChls[0], _2);
        thrd.join();
    }
	//AsyncPsiSender sender;
	//AsyncPsiReceiver recv;
	BitVector recvOutput(setSize);

	u64 otRecvIdx = 4;
	u64 otSendIdx = 4;
	std::vector<std::thread> sendThrds(setSize), recvThrds(setSize);
	std::vector<AsyncPsiSender> sendPSIs(repeatCount);
	std::vector<AsyncPsiReceiver> recvPSIs(repeatCount);

	std::thread thrd0([&]() {

		for (u64 j = 0; j < repeatCount; ++j)
		{
			u64 otIdx = 0;
			sendPSIs[j].init(setSize, psiSecParam, *sendChls[0], OTSender, otIdx, prng);
		}
	});

	for (u64 j = 0; j < repeatCount; ++j)
	{
		u64 otIdx = 0;
		recvPSIs[j].init(setSize, psiSecParam, *recvChls[0], OTRecver, otIdx);
	}
	thrd0.join();

	for (u64 i = 0; i < setSize; ++i)
	{
		sendThrds[i] = std::thread([&, i]() {
			for (u64 j = 0; j < repeatCount; ++j)
			{


				AsyncPsiSender& sender = sendPSIs[j];
				//BitVector recvOutput(setSize);


				sender.AsyncCommitSend(sendSet[i], *sendChls[i], i);

				sender.AsyncCommitRecv(*sendChls[i], i);

				//	for (u64 i = 0; i < setSize; ++i)
				sender.open(*sendChls[i], i);
			}
		});

		recvThrds[i] = std::thread([&, i]() {
			for (u64 j = 0; j < repeatCount; ++j)
			{
				AsyncPsiReceiver& recv = recvPSIs[j];
				Timer time;
				u64 otIdx = 0;
				//recv.init(setSize, psiSecParam, recvChl, OTRecver, otIdx);

				//for (u64 i = 0; i < setSize; ++i)
				recv.CommitSend(recvSet[i], *recvChls[i], i);

				//for (u64 i = 0; i < setSize; ++i)
				recv.CommitRecv(*recvChls[i], i);

				//recv.open(recvOutput, recvChl, time);

				if (recv.open(*recvChls[i], i, Role::First))
					throw UnitTestFail();
				//}
			}

		});
	}
	for (u64 i = 0; i < setSize; ++i)
	{
		sendThrds[i].join();
		recvThrds[i].join();
		sendChls[i]->close();
		recvChls[i]->close();
	}

	ep0.stop();
	ep1.stop();
	ios.stop();

	//thrd.join();

	//recvChl.Close();
	//sendChl.Close();
}


void AsyncPsi_FullSet_Test_Impl()
{
	setThreadName("CP_Test_Thread");
	u64 repeatCount = 4;
	u64 setSize = 9, psiSecParam = 41;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = recvSet[i] = prng.get<block>();
	}

	std::shuffle(sendSet.begin(), sendSet.end(), prng);


	std::string name("psi");
	//NetworkManager netMgr0("localhost", 1212, 4, true);
	//NetworkManager netMgr1("localhost", 1212, 4, false);
	//auto sendChls = netMgr0.AddChannels(name, setSize);
	//auto recvChls = netMgr1.AddChannels(name, setSize);

	BtIOService ios(0);
	BtEndpoint ep0(ios, "localhost", 1212, true, name);
	BtEndpoint ep1(ios, "localhost", 1212, false, name);
	std::vector<Channel*> sendChls(setSize), recvChls(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		recvChls[i] = &ep1.addChannel(name + std::to_string(i), name + std::to_string(i));
		sendChls[i] = &ep0.addChannel(name + std::to_string(i), name + std::to_string(i));
	}
	//OTOracleSender OTSender(prng, AsyncPsiSender::PsiOTCount(setSize, psiSecParam));
	//OTOracleReceiver OTRecver(OTSender, prng, AsyncPsiSender::PsiOTCount(setSize, psiSecParam));

    BDX_OTExtReceiver OTRecver;
    BDX_OTExtSender OTSender;
    {
        std::atomic<u64> _1(0), _2(0);
        std::array<block, 128> baseRecvMsg;
        BitVector baseRecvChoice(128); baseRecvChoice.randomize(prng);
        std::array<std::array<block, 2>, 128>baseSendMsg;
        prng.get(baseSendMsg.data(), baseSendMsg.size());
        for (u64 i = 0; i < 128; ++i)
        {
            baseRecvMsg[i] = baseSendMsg[i][baseRecvChoice[i]];
        }
        u64 numOTs = AsyncPsiSender::PsiOTCount(setSize, psiSecParam) ;
        auto thrd = std::thread([&]() {OTRecver.Extend(baseSendMsg, numOTs, prng, *recvChls[0], _1); });
        OTSender.Extend(baseRecvMsg, baseRecvChoice, numOTs, prng, *sendChls[0], _2);
        thrd.join();
    }

	AsyncPsiSender sender;
	AsyncPsiReceiver recv;
	BitVector recvOutput(setSize);

	u64 otRecvIdx = 4;
	u64 otSendIdx = 4;
	std::vector<std::thread> sendThrds(setSize), recvThrds(setSize);
	std::vector<AsyncPsiSender> sendPSIs(repeatCount);
	std::vector<AsyncPsiReceiver> recvPSIs(repeatCount);

	std::thread([&]() {

		for (u64 j = 0; j < repeatCount; ++j)
		{
			u64 otIdx = 0;
			sendPSIs[j].init(setSize, psiSecParam, *sendChls[0], OTSender, otIdx, prng);
		}
	}).join();

	for (u64 j = 0; j < repeatCount; ++j)
	{
		u64 otIdx = 0;
		recvPSIs[j].init(setSize, psiSecParam, *recvChls[0], OTRecver, otIdx);
	}


	for (u64 i = 0; i < setSize; ++i)
	{
		sendThrds[i] = std::thread([&, i]() {
			for (u64 j = 0; j < repeatCount; ++j)
			{


				AsyncPsiSender& sender = sendPSIs[j];
				//BitVector recvOutput(setSize);


				sender.AsyncCommitSend(sendSet[i], *sendChls[i], i);

				sender.AsyncCommitRecv(*sendChls[i], i);

				//	for (u64 i = 0; i < setSize; ++i)
				sender.open(*sendChls[i], i);
			}
		});

		recvThrds[i] = std::thread([&, i]() {
			for (u64 j = 0; j < repeatCount; ++j)
			{
				AsyncPsiReceiver& recv = recvPSIs[j];
				Timer time;
				u64 otIdx = 0;
				//recv.init(setSize, psiSecParam, recvChl, OTRecver, otIdx);

				//for (u64 i = 0; i < setSize; ++i)
				recv.CommitSend(recvSet[i], *recvChls[i], i);

				//for (u64 i = 0; i < setSize; ++i)
				recv.CommitRecv(*recvChls[i], i);

				//recv.open(recvOutput, recvChl, time);

				if (!recv.open(*recvChls[i], i, Role::First))
					throw UnitTestFail();
				//}
			}

		});
	}
	for (u64 i = 0; i < setSize; ++i)
	{
		sendThrds[i].join();
		recvThrds[i].join();
		sendChls[i]->close();
		recvChls[i]->close();
	}

	ep0.stop();
	ep1.stop();
	ios.stop();


}

void AsyncPsi_SingltonSet_Test_Impl()
{
	setThreadName("Sender");
	//InitDebugPrinting("..\\test.out");
	u64 repeatCount = 4;
	u64 setSize = 1, psiSecParam = 8;
	u64 otCount = AsyncPsiSender::PsiOTCount(setSize, psiSecParam);

	PRNG prng(_mm_set_epi32(4253465, 34354565, 234435, 23987045));

	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = prng.get<block>();
		recvSet[i] = prng.get<block>();
	}

	sendSet[setSize / 2] = recvSet[0] = _mm_set_epi64x(0x821a95f854c51389,0x17df233bc55016c3);

	std::string name("psi");

	//NetworkManager netMgr0("localhost", 1212, 4, true);
	//NetworkManager netMgr1("localhost", 1212, 4, false);
	//auto sendChls = netMgr0.AddChannels(name, setSize);
	//auto recvChls = netMgr1.AddChannels(name, setSize);
	BtIOService ios(0);
	BtEndpoint ep0(ios, "localhost", 1212, true, name);
	BtEndpoint ep1(ios, "localhost", 1212, false, name);
	std::vector<Channel*> sendChls(setSize), recvChls(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		recvChls[i] = &ep1.addChannel(name + std::to_string(i), name + std::to_string(i));
		sendChls[i] = &ep0.addChannel(name + std::to_string(i), name + std::to_string(i));
	}
	Timer tt;

	//OTOracleSender OTSender(prng, otCount * repeatCount + 4);
	//OTOracleReceiver OTRecver(OTSender, prng, otCount * repeatCount + 4);

    BDX_OTExtReceiver OTRecver;
    BDX_OTExtSender OTSender;
    {
        std::atomic<u64> _1(0), _2(0);
        std::array<block, 128> baseRecvMsg;
        BitVector baseRecvChoice(128); baseRecvChoice.randomize(prng);
        std::array<std::array<block, 2>, 128>baseSendMsg;
        prng.get(baseSendMsg.data(), baseSendMsg.size());
        for (u64 i = 0; i < 128; ++i)
        {
            baseRecvMsg[i] = baseSendMsg[i][baseRecvChoice[i]];
        }
        u64 numOTs = AsyncPsiSender::PsiOTCount(setSize, psiSecParam) * repeatCount + 4;
        auto thrd = std::thread([&]() {OTRecver.Extend(baseSendMsg, numOTs, prng, *recvChls[0], _1); });
        OTSender.Extend(baseRecvMsg, baseRecvChoice, numOTs, prng, *sendChls[0], _2);
        thrd.join();
    }
	u64 otRecvIdx = 4;
	u64 otSendIdx = 4;
	std::vector<std::thread> sendThrds(setSize), recvThrds(setSize);
	std::vector<AsyncPsiSender> sendPSIs(repeatCount);
	std::vector<AsyncPsiReceiver> recvPSIs(repeatCount);
	
	tt.setTimePoint("start");

	std::thread([&]() {

		for (u64 j = 0; j < repeatCount; ++j)
		{
			u64 otIdx = 4;
			sendPSIs[j].init(setSize, psiSecParam, *sendChls[0], OTSender, otIdx, prng);
		}
	}).join();

	for (u64 j = 0; j < repeatCount; ++j)
	{
		u64 otIdx = 4;
		recvPSIs[j].init(setSize, psiSecParam, *recvChls[0], OTRecver, otIdx);
	}

	tt.setTimePoint("initDone");

	for (u64 i = 0; i < setSize; ++i)
	{
		sendThrds[i] = std::thread([&, i]() {
			for (u64 j = 0; j < repeatCount; ++j)
			{


				AsyncPsiSender& sender = sendPSIs[j];
				//BitVector recvOutput(setSize);



				sender.AsyncCommitSend(sendSet[i], *sendChls[i], i);


				sender.AsyncCommitRecv(*sendChls[i], i);


				//	for (u64 i = 0; i < setSize; ++i)
				sender.open(*sendChls[i], i);

			}
		});

		recvThrds[i] = std::thread([&, i]() {
			for (u64 j = 0; j < repeatCount; ++j)
			{
				AsyncPsiReceiver& recv = recvPSIs[j];
				Timer time;
				u64 otIdx = 0;
				//recv.init(setSize, psiSecParam, recvChl, OTRecver, otIdx);

				if (!i) tt.setTimePoint("start");

				//for (u64 i = 0; i < setSize; ++i)
				recv.CommitSend(recvSet[i], *recvChls[i], i);
				if (!i) tt.setTimePoint("Commit");

				//for (u64 i = 0; i < setSize; ++i)
				recv.CommitRecv(*recvChls[i], i);

				if (!i) tt.setTimePoint("comRecv");
				//recv.open(recvOutput, recvChl, time);

			//	for (u64 i = 0; i < setSize; ++i)
				{
					if (i == 0)
					{

						if (!recv.open(*recvChls[i], i, Role::First))
							throw UnitTestFail();
					}
					else
						if (recv.open(*recvChls[i], i, Role::First))
							throw UnitTestFail();
				}
				if (!i) tt.setTimePoint("open");
			}

		});
	}
	for (u64 i = 0; i < setSize; ++i)
	{
		sendThrds[i].join();
		recvThrds[i].join();
		sendChls[i]->close();
		recvChls[i]->close();
	}
	//std::cout << tt << std::endl;

	ep0.stop();
	ep1.stop();
	ios.stop();


}
