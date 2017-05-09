#include "CircuitPackage_Tests.h"
#include "cryptoTools/Network/Endpoint.h"

#include "Common.h"
#include "cryptoTools/Common/Defines.h"
#include "DualEx/CircuitPackage.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Common/Log.h"

#include <array>
#include "DebugCircuits.h"

using namespace osuCrypto;

void CircuitPackage_BitAdder_Test_Impl()
{

	setThreadName("CP_Test_Thread");

	Circuit c = AdderCircuit(4);

	std::string name("psi");

	IOService ios(0);
	Endpoint ep0(ios, "localhost", 1212, EpMode::Server, name);
	Endpoint ep1(ios, "localhost", 1212, EpMode::Client, name);
	Channel recvChl = ep1.addChannel(name, name);
	Channel sendChl = ep0.addChannel(name, name);

	PRNG prng(_mm_set_epi32(4253465, 3434565, 87654, 23987045));

	KProbeMatrix kprobe(c.Inputs()[Role::First], 40, prng);

	//OTOracleSender OTSend(prng, kprobe.encodingSize());
	//OTOracleReceiver OTRecv(OTSend, prng, kprobe.encodingSize());

    std::atomic<u64> _1(0), _2(0);
    BDX_OTExtReceiver OTRecv;
    BDX_OTExtSender OTSend;
    std::array<block, 128> baseRecvMsg;
    BitVector baseRecvChoice(128); baseRecvChoice.randomize(prng);
    std::array<std::array<block, 2>, 128>baseSendMsg;
    prng.get(baseSendMsg.data(), baseSendMsg.size());
    for (u64 i = 0; i < 128; ++i)
    {
        baseRecvMsg[i] = baseSendMsg[i][baseRecvChoice[i]];
    }
    u64 numOTs = kprobe.encodingSize();
    auto thrd = std::thread([&]() {OTRecv.Extend(baseSendMsg, numOTs, prng, recvChl, _1); });
    OTSend.Extend(baseRecvMsg, baseRecvChoice, numOTs, prng, sendChl, _2);
    thrd.join();




	std::vector<block> indexArray(kprobe.encodingSize());
	for (u64 i = 0; i < indexArray.size(); ++i) indexArray[i] = _mm_set_epi64x(0, i);

	u64 otIdx = 0;
	CircuitPackage cp;
	std::vector<block> wireBuff(c.WireCount());
#ifdef ADAPTIVE_SECURE
	std::vector<block> adaptiveSecureMasks(std::max(c.NonXorGateCount() * 2, kprobe.encodingSize()));
	cp.init(c, Role::First, prng, sendChl, 0, kprobe, wireBuff, indexArray, adaptiveSecureMasks);
#else
	cp.init(c, Role::First, prng, sendChl, 0, wireBuff);
#endif
	cp.initOT(c, Role::First, sendChl,kprobe, OTRecv, otIdx);

	otIdx = 0;
	CommCircuitPackage ccp;
	ccp.init(c, kprobe, recvChl, 0);
	ccp.initOT(recvChl, kprobe, OTSend, otIdx, c.Inputs()[Role::First]);

	CircuitPackage cp2(std::move(cp));
	CommCircuitPackage ccp2(std::move(ccp));

	block xor1 = ZeroBlock;
	cp2.open(c, sendChl, Role::First, xor1);

	block xor2 = ZeroBlock;

	ccp2.open(c, kprobe, kprobe, Role::Second, recvChl, xor2, indexArray
#ifdef ADAPTIVE_SECURE
		,adaptiveSecureMasks
#endif
		);

	cp2.clear();
	ccp2.clear();

	sendChl.close();
	recvChl.close();

	ep0.stop();
	ep1.stop();
	ios.stop();
}
