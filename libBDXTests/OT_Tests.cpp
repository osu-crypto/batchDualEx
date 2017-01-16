#include "OT_Tests.h"


#include "OT/OTExtReceiver.h"
#include "OT/OTExtSender.h"
#include "cryptoTools/Network/BtChannel.h"
#include "cryptoTools/Network/BtEndpoint.h"

#include "cryptoTools/Common/Log.h"
#include "Common.h"
#include <thread>
#include <vector>

#ifdef GetMessage
#undef GetMessage
#endif

using namespace osuCrypto;


void OT_100Receive_Test(BDX_OTExtReceiver& recv, BDX_OTExtSender& sender)
{

	for (u64 i = 0; i < 100; ++i)
	{

		u8 choice = recv.mChoiceBits[i];
		const block & revcBlock = recv.GetMessage(i);
		//(i, choice, revcBlock);
		const block& senderBlock = sender.GetMessage(i, choice);



		if (neq(revcBlock, senderBlock))
			throw UnitTestFail();

		if (eq(revcBlock, sender.GetMessage(i, !choice)))
			throw UnitTestFail();
	}

}



void BitVector_Indexing_Test_Impl()
{
	BitVector bb(128);
	std::vector<bool>gold(128);


	for (u64 i : std::vector<u64>{ { 2,33,34,26,85,33,99,12,126 } })
	{
		bb[i] = gold[i] = true;
	}


	for (auto i = 0; i < 128; ++i)
	{
		if ((bool)bb[i] != gold[i])
			throw std::runtime_error("");

		if ((bool)bb[i] != gold[i])
			throw UnitTestFail();
	}
}

void BitVector_Parity_Test_Impl()
{
	PRNG prng(ZeroBlock);
	for (u64 i = 0; i < 1000; ++i)
	{
		u8 size = prng.get<u8>();
		u8 parity = 0;

		BitVector bv(size);

		bv.randomize(prng);

		for (u64 j = 0; j < size; ++j)
		{
			parity ^= bv[j];
		}

		if (parity != bv.parity())
			throw UnitTestFail();
	}

}

void BitVector_Append_Test_Impl()
{
	
	BitVector bv0(3);
	BitVector bv1(6);
	BitVector bv2(9);
	BitVector bv4;


	bv0[0] = 1; bv2[0] = 1;
	bv0[2] = 1; bv2[2] = 1;
	bv1[2] = 1; bv2[3 + 2] = 1;
	bv1[5] = 1; bv2[3 + 5] = 1;

	bv4.append(bv0);
	bv4.append(bv1);

	std::cout << bv0 << bv1 << std::endl;
	std::cout << bv2 << std::endl;
	std::cout << bv4 << std::endl;

	if (bv4 != bv2)
		throw UnitTestFail();
}


void BitVector_Copy_Test_Impl()
{
	u64 offset = 3;
	BitVector bb(128), c(128 - offset);


	for (u64 i : std::vector<u64>{ { 2,33,34,26,85,33,99,12,126 } })
	{
		bb[i] = true;
	}

	c.copy(bb, offset, 128 - offset);


	std::cout << "bb ";// << bb << Lgger::endl;
	for (u64 i = 0; i < bb.size(); ++i)
	{
		if (bb[i]) std::cout << "1";
		else std::cout << "0";

	}
	std::cout << std::endl;
	std::cout << "c   ";
	for (u64 i = 0; i < c.size(); ++i)
	{
		if (c[i]) std::cout << "1";
		else std::cout << "0";

	}
	std::cout << std::endl;

	for (u64 i = 0; i < 128 - offset; ++i)
	{
		if (bb[i + offset] != c[i])
			throw std::runtime_error("");

	}
}

void printMtx(std::array<block, 128>& data)
{
	for (auto& d : data)
	{
		std::cout << d << std::endl;
	}
}

void OTExt_100Receive_Test_Impl()
{
		setThreadName("Sender");

		std::string name("ss");
		BtIOService ios(0);
		BtEndpoint ep0(ios, "localhost", 1212, true, name);
		BtEndpoint ep1(ios, "localhost", 1212, false, name);
		Channel& recvChannel = ep1.addChannel(name, name);
		Channel& senderChannel = ep0.addChannel(name, name);

		//NetworkManager senderNetMgr("localhost", 1212, 1, true);
		//NetworkManager recvNetMgr("localhost", 1212, 1, false);

		//auto& senderChannel = senderNetMgr.addChannel("OTExt");
		//auto& recvChannel = recvNetMgr.addChannel("OTExt");

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));

		u64 numOTs = 100;	
		std::atomic<u64> sendedDoneIdx(0), recvDoneIdx(0);


		BDX_OTExtSender sender;
		BDX_OTExtReceiver recv;

        std::array<block, 128> baseRecvMsg;
        BitVector baseRecvChoice(128); baseRecvChoice.randomize(prng0);
        std::array<std::array<block, 2>, 128>baseSendMsg;
        prng0.get(baseSendMsg.data(), baseSendMsg.size());
        for (u64 i = 0; i < 128; ++i)
        {
            baseRecvMsg[i] = baseSendMsg[i][baseRecvChoice[i]];
        }


		std::thread thrd = std::thread([&]() {
			setThreadName("receiver");

			//{
			//	std::lock_guard<std::mutex> lock(Lg::mMtx);
			//	for (u64 i = 0; i < baseOTs.receiver_outputs.size(); ++i)
			//	{
			//		std::cout << "i  " << baseOTs.sender_inputs[i][0] << " " << baseOTs.sender_inputs[i][1] << std::endl;
			//	}
			//}
			recv.Extend(baseSendMsg, numOTs, prng0, recvChannel, recvDoneIdx);
		});


		sender.Extend(baseRecvMsg, baseRecvChoice, numOTs, prng1, senderChannel, sendedDoneIdx);
		thrd.join();

		//for (u64 i = 0; i < baseOTs.receiver_outputs.size(); ++i)
		//{
		//	std::cout << sender.GetMessage(i, 0) << " " << sender.GetMessage(i, 1) << "\n" << recv.GetMessage(1) << "  " << recv.mChoiceBits[i] << std::endl;
		//}

		OT_100Receive_Test(recv, sender);


		senderChannel.close();
		recvChannel.close();
		ep0.stop();
		ep1.stop();
		ios.stop();

		//senderNetMgr.Stop();
		//recvNetMg
}



