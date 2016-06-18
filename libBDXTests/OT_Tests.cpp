#include "OT_Tests.h"

#include "OT/OTExtInterface.h"

#include "OT/Tools.h"

#include "OT/OTExtReceiver.h"
#include "OT/OTExtSender.h"
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"

#include "Common/Logger.h"
#include "Common.h"
#include <thread>
#include <vector>

#ifdef GetMessage
#undef GetMessage
#endif

using namespace libBDX;


void OT_100Receive_Test(I_OTExtReceiver& recv, I_OTExtSender& sender)
{

	for (u64 i = 0; i < 100; ++i)
	{

		u8 choice = recv.mChoiceBits[i];
		const block & revcBlock = recv.GetMessage(i);
		//(i, choice, revcBlock);
		const block& senderBlock = sender.GetMessage(i, choice);



		if (notEqual(revcBlock, senderBlock))
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
		u8 size = prng.get_uchar();
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

	Lg::out << bv0 << bv1 << Lg::endl;
	Lg::out << bv2 << Lg::endl;
	Lg::out << bv4 << Lg::endl;

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


	Lg::out << "bb ";// << bb << Lgger::endl;
	for (u64 i = 0; i < bb.size(); ++i)
	{
		if (bb[i]) Lg::out << "1";
		else Lg::out << "0";

	}
	Lg::out << Lg::endl;
	Lg::out << "c   ";
	for (u64 i = 0; i < c.size(); ++i)
	{
		if (c[i]) Lg::out << "1";
		else Lg::out << "0";

	}
	Lg::out << Lg::endl;

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
		Lg::out << d << Lg::endl;
	}
}

void Transpose_Test_Impl()
{



	std::array<block, 128> data;
	memset((u8*)data.data(),0, sizeof(data));

	data[0] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
	data[1] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
	data[2] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
	data[3] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
	data[4] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
	data[5] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
	data[6] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
	data[7] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);

	printMtx(data);
	eklundh_transpose128(data);


	for (auto& d : data)
	{
		if (notEqual(d, _mm_set_epi64x(0, 0xFF)))
		{
			Lg::out << "expected" << Lg::endl;
			Lg::out << _mm_set_epi64x(0xF, 0) << Lg::endl << Lg::endl;

			printMtx(data);

			throw UnitTestFail();
		}
	}
}


void OTExt_100Receive_Test_Impl()
{
		Lg::setThreadName("Sender");

		Lg::EnableTag(Lg::BaseOT);
		Lg::EnableTag(Lg::ExtSendOT);
		Lg::EnableTag(Lg::ExtRecvOT);
		Lg::EnableTag(Lg::NetMgr);

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


		OTExtSender sender;
		OTExtReceiver recv;

		std::thread thrd = std::thread([&]() {
			Lg::setThreadName("receiver");
			BaseOT baseOTs(recvChannel, OTRole::Sender);

			baseOTs.exec_base(prng0);

			baseOTs.check();

			//{
			//	std::lock_guard<std::mutex> lock(Lg::mMtx);
			//	for (u64 i = 0; i < baseOTs.receiver_outputs.size(); ++i)
			//	{
			//		Lg::out << "i  " << baseOTs.sender_inputs[i][0] << " " << baseOTs.sender_inputs[i][1] << Lg::endl;
			//	}
			//}
			recv.Extend(baseOTs.sender_inputs,numOTs, prng0, recvChannel, recvDoneIdx);
		});


		BaseOT baseOTs(senderChannel, OTRole::Receiver);
		
		baseOTs.exec_base(prng1);

		baseOTs.check();

		//{
		//	std::lock_guard<std::mutex> lock(Lg::mMtx);
		//	for (u64 i = 0; i < baseOTs.receiver_outputs.size(); ++i)
		//	{
		//		Lg::out << "i  " << baseOTs.receiver_outputs[i] << " " << (int)baseOTs.receiver_inputs[i] << Lg::endl;
		//	}
		//}

		sender.Extend(baseOTs.receiver_outputs, baseOTs.receiver_inputs, numOTs, prng1, senderChannel, sendedDoneIdx);
		thrd.join();

		//for (u64 i = 0; i < baseOTs.receiver_outputs.size(); ++i)
		//{
		//	Lg::out << sender.GetMessage(i, 0) << " " << sender.GetMessage(i, 1) << "\n" << recv.GetMessage(1) << "  " << recv.mChoiceBits[i] << Lg::endl;
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



