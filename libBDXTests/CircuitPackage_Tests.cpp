#include "CircuitPackage_Tests.h"
#include "Network/BtEndpoint.h"

#include "Common.h"
#include "Common/Defines.h"
#include "DualEx/CircuitPackage.h"
#include "Network/Channel.h"
#include "OTOracleReceiver.h"
#include "OTOracleSender.h"
#include "Common/Logger.h"

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include <array>
#include "DebugCircuits.h"


void CircuitPackage_BitAdder_Test_Impl()
{

	Lg::setThreadName("CP_Test_Thread");

	Circuit c = AdderCircuit(4);

	std::string name("psi");

	BtIOService ios(0);
	BtEndpoint ep0(ios, "localhost", 1212, true, name);
	BtEndpoint ep1(ios, "localhost", 1212, false, name);
	Channel& recvChl = ep1.addChannel(name, name);
	Channel& sendChl = ep0.addChannel(name, name);
	//NetworkManager sendNetMgr("localhost", 1212, 4, true);
	//NetworkManager recvNetMgr("localhost", 1212, 4, false);

	PRNG prng(_mm_set_epi32(4253465, 3434565, 87654, 23987045));
	//Channel& sendChl = sendNetMgr.addChannel("cp");
	//Channel& recvChl = recvNetMgr.addChannel("cp");

	KProbeMatrix kprobe(c.Inputs()[Role::First], 40, prng);

	OTOracleSender OTSend(prng, kprobe.encodingSize());
	OTOracleReceiver OTRecv(OTSend, prng, kprobe.encodingSize());

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
