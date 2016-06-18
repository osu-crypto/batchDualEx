#include "PSI_Tests.h"

#include "Common.h"
#include "Common/Defines.h"
#include "PSI/PSIReceiver.h"
#include "PSI/PSISender.h"
#include "Network/BtEndpoint.h"
#include "OTOracleReceiver.h"
#include "OTOracleSender.h"
#include "Common/Logger.h"
//
//#include "cryptopp/aes.h"
//#include "cryptopp/modes.h"
//#include "MyAssert.h"
#include <array>

using namespace libBDX;

void Psi_EmptrySet_Test_Impl()
{
	u64 repeatCount = 4;
	u64 setSize = 14, psiSecParam = 40;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = prng.get_block();
		recvSet[i] = prng.get_block();
	}

	std::string name("psi");

	BtIOService ios(0);
	BtEndpoint ep0(ios, "localhost", 1212, true, name);
	BtEndpoint ep1(ios, "localhost", 1212, false, name);
	std::vector<Channel*> sendChls(setSize), recvChls(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		recvChls[i] = &ep1.addChannel(name + std::to_string(i), name + std::to_string(i));
		sendChls[i] = &ep0.addChannel(name + std::to_string(i), name + std::to_string(i));
	}

	OTOracleSender OTSender(prng, PsiSender::PsiOTCount(setSize, psiSecParam) * repeatCount);
	OTOracleReceiver OTRecver(OTSender, prng, PsiReceiver::PsiOTCount(setSize, psiSecParam)*repeatCount);

	//PsiSender sender;
	//PsiReceiver recv;
	BitVector recvOutput(setSize);

	u64 otRecvIdx = 4;
	u64 otSendIdx = 4;
	std::vector<std::thread> sendThrds(setSize), recvThrds(setSize);
	std::vector<PsiSender> sendPSIs(repeatCount);
	std::vector<PsiReceiver> recvPSIs(repeatCount);

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


				PsiSender& sender = sendPSIs[j];
				//BitVector recvOutput(setSize);

#ifdef ASYNC_PSI

				sender.AsyncCommitSend(sendSet[i], *sendChls[i], i);

				sender.AsyncCommitRecv(*sendChls[i], i);
#else
				sender.CommitRecv(*sendChls[i], i);

				sender.CommitSend(sendSet[i], *sendChls[i], i);
#endif
				//	for (u64 i = 0; i < setSize; ++i)
				sender.open(*sendChls[i], i);
			}
		});

		recvThrds[i] = std::thread([&, i]() {
			for (u64 j = 0; j < repeatCount; ++j)
			{
				PsiReceiver& recv = recvPSIs[j];
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


void Psi_FullSet_Test_Impl()
{
	Lg::setThreadName("CP_Test_Thread");
	u64 repeatCount = 4;
	u64 setSize = 9, psiSecParam = 41;
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = recvSet[i] = prng.get_block();
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
	OTOracleSender OTSender(prng, PsiSender::PsiOTCount(setSize, psiSecParam));
	OTOracleReceiver OTRecver(OTSender, prng, PsiSender::PsiOTCount(setSize, psiSecParam));

	PsiSender sender;
	PsiReceiver recv;
	BitVector recvOutput(setSize);

	u64 otRecvIdx = 4;
	u64 otSendIdx = 4;
	std::vector<std::thread> sendThrds(setSize), recvThrds(setSize);
	std::vector<PsiSender> sendPSIs(repeatCount);
	std::vector<PsiReceiver> recvPSIs(repeatCount);

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


				PsiSender& sender = sendPSIs[j];
				//BitVector recvOutput(setSize);

#ifdef ASYNC_PSI

				sender.AsyncCommitSend(sendSet[i], *sendChls[i], i);

				sender.AsyncCommitRecv(*sendChls[i], i);
#else
				sender.CommitRecv(*sendChls[i], i);

				sender.CommitSend(sendSet[i], *sendChls[i], i);
#endif
				//	for (u64 i = 0; i < setSize; ++i)
				sender.open(*sendChls[i], i);
			}
		});

		recvThrds[i] = std::thread([&, i]() {
			for (u64 j = 0; j < repeatCount; ++j)
			{
				PsiReceiver& recv = recvPSIs[j];
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

void Psi_SingltonSet_Test_Impl()
{
	Lg::setThreadName("Sender");
	//InitDebugPrinting("..//test.out");
	u64 repeatCount = 4;
	u64 setSize = 8, psiSecParam = 40;
	u64 otCount = PsiSender::PsiOTCount(setSize, psiSecParam);

	PRNG prng(_mm_set_epi32(4253465, 34354565, 234435, 23987045));

	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = prng.get_block();
		recvSet[i] = prng.get_block();
	}

	sendSet[setSize / 2] = recvSet[0];

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

	OTOracleSender OTSender(prng, otCount * repeatCount + 4);
	OTOracleReceiver OTRecver(OTSender, prng, otCount * repeatCount + 4);

	u64 otRecvIdx = 4;
	u64 otSendIdx = 4;
	std::vector<std::thread> sendThrds(setSize), recvThrds(setSize);
	std::vector<PsiSender> sendPSIs(repeatCount);
	std::vector<PsiReceiver> recvPSIs(repeatCount);

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


				PsiSender& sender = sendPSIs[j];
				//BitVector recvOutput(setSize);

#ifdef ASYNC_PSI

				sender.AsyncCommitSend(sendSet[i], *sendChls[i], i);

				sender.AsyncCommitRecv(*sendChls[i], i);
#else
				sender.CommitRecv(*sendChls[i], i);

				sender.CommitSend(sendSet[i], *sendChls[i], i);
#endif
				//	for (u64 i = 0; i < setSize; ++i)
				sender.open(*sendChls[i], i);
			}
		});

		recvThrds[i] = std::thread([&, i]() {
			for (u64 j = 0; j < repeatCount; ++j)
			{
				PsiReceiver& recv = recvPSIs[j];
				Timer time;
				u64 otIdx = 0;
				//recv.init(setSize, psiSecParam, recvChl, OTRecver, otIdx);

				//for (u64 i = 0; i < setSize; ++i)
				recv.CommitSend(recvSet[i], *recvChls[i], i);

				//for (u64 i = 0; i < setSize; ++i)
				recv.CommitRecv(*recvChls[i], i);

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

	for (u64 j = 0; j < repeatCount; ++j)
	{
		PsiReceiver& recv = recvPSIs[j];
		auto& send = sendPSIs[j];

		Lg::out << Lg::endl << recv.timer << Lg::endl;
		Lg::out << Lg::endl << send.timer << Lg::endl;
	}
	ep0.stop();
	ep1.stop();
	ios.stop();


}




void Psi_SingltonSet_Serial_Test_Impl()
{
	Lg::setThreadName("Sender");
	//InitDebugPrinting("..//test.out");
	u64 setSize = 2, psiSecParam = 8;
	u64 otCount = PsiSender::PsiOTCount(setSize, psiSecParam);

	PRNG prng(_mm_set_epi32(4253465, 34354565, 234435, 23987045));

	std::vector<block> sendSet(setSize), recvSet(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		sendSet[i] = prng.get_block();
		recvSet[i] = prng.get_block();
	}

	sendSet[setSize / 2] = recvSet[0];

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

	OTOracleSender OTSender(prng, otCount);
	OTOracleReceiver OTRecver(OTSender, prng, otCount);

	u64 otRecvIdx = 4;
	u64 otSendIdx = 4;
	std::thread sendThrds;
	PsiSender sendPSIs;
	PsiReceiver recvPSIs;

	auto sendThrd = std::thread([&]() {

		u64 otIdx = 0;
		sendPSIs.init(setSize, psiSecParam, *sendChls[0], OTSender, otIdx, prng);

		PsiSender& sender = sendPSIs;
		//BitVector recvOutput(setSize);

		for (u64 i = 0; i < setSize; ++i)
		{
			sender.CommitRecv(*sendChls[i], i);
		}


		for (u64 i = 0; i < setSize; ++i)
		{
			sender.CommitSend(sendSet[i], *sendChls[i], i);
		}
		//	for (u64 i = 0; i < setSize; ++i)


		for (u64 i = 0; i < setSize; ++i)
		{
			sender.open(*sendChls[i], i);
		}
	});

	u64 otIdx = 0;
	recvPSIs.init(setSize, psiSecParam, *recvChls[0], OTRecver, otIdx);

	PsiReceiver& recv = recvPSIs;
	//recv.init(setSize, psiSecParam, recvChl, OTRecver, otIdx);

	for (u64 i = 0; i < setSize; ++i)
		recv.CommitSend(recvSet[i], *recvChls[i], i);

	for (u64 i = 0; i < setSize; ++i)
		recv.CommitRecv(*recvChls[i], i);

	BitVector result(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{
		result[i] = recv.open(*recvChls[i], i, Role::First);

		if ((bool)result[i] == (bool)i)
			throw std::runtime_error("");
	}


	sendThrd.join();

	for (u64 i = 0; i < setSize; ++i)
	{
		sendChls[i]->close();
		recvChls[i]->close();
	}

	ep0.stop();
	ep1.stop();
	ios.stop();


}
