#include "Common/Logger.h"
#include <functional>

#include "AES128_Tests.h"
//#include "CBC_MAC_Tests.h"
#include "Circuit_Tests.h"
#include "CircuitPackage_Tests.h"
#include "DualExActor_Tests.h"
#include "HalfGtGarbledCircuit_Tests.h"
#include "Circuit/KProbeResistant.h"
#include "KProbe_Tests.h"
#include "BtChannel_Tests.h"
#include "OT_Tests.h"
#include "PSI_Tests.h"
#include "AsyncPSI_Tests.h"

using namespace libBDX;

void run(std::string name, std::function<void(void)> func)
{
	Lg::out << name;

	auto start = std::chrono::high_resolution_clock::now();
	try 
	{
		func(); Lg::out << Lg::Color::Green << "  Passed" << Lg::ColorDefault;
	} 
	catch (const std::exception& e) 
	{
		Lg::out << Lg::Color::Red << "Failed - " << e.what() << Lg::ColorDefault;
	}

	auto end = std::chrono::high_resolution_clock::now();

	u64 time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	 
	Lg::out << "   " << time << "ms" << Lg::endl;


	if (Lg::out.mSink != &std::cout)
		throw std::runtime_error("");
}


void AES128_all()
{
	Lg::out << Lg::endl;
	run("AES128_Enc                    ", AES128_Enc_Test_Impl);
	run("AES128_Encblock4              ", AES128_Encblock4_Test_Impl);
	run("AES128_EncFewblocks           ", AES128_EncFewblocks_Test_Impl);
	run("AES128_EncManyblocks          ", AES128_EncManyblocks_Test_Impl);
}								      
								      
						      
void Circuit_all()				      
{								      
	Lg::out << Lg::endl;		      
	run("Circuit_BrisRead_Adder32      ", Circuit_BrisRead_Adder32_Test_Impl);
	//run("Circuit_BrisRead_AES          ", Circuit_BrisRead_AES_Test_Impl);
	//run("Circuit_BrisRead_SHA          ", Circuit_BrisRead_SHA_Test_Impl);
	run("Circuit_Gen_Adder32           ", Circuit_Gen_Adder32_Test_Impl);
	run("DagCircuit_BrisRead_Adder32   ", DagCircuit_BrisRead_Adder32_Test_Impl);
	run("DagCircuit_RandomReduce       ", DagCircuit_RandomReduce_Test_Impl);
}

void CircuitPackage_all()
{
	Lg::out << Lg::endl;
	run("CircuitPackage_BitAdder       ", CircuitPackage_BitAdder_Test_Impl);
}
void DualExActor_all()
{
	Lg::out << Lg::endl;
	run("DualExActor_BitAdder          ", DualExActor_BitAdder_Complete_Test_Impl);
	run("DualExActor_BitAdder_ConEval  ", DualExActor_BitAdder_Concurrent_Test_Impl);
}

void PSI_all()
{
	

		Lg::out << Lg::endl;
		run("AsyncPsi_FullSet_Test_Impl     ", AsyncPsi_FullSet_Test_Impl);
		run("AsyncPsi_SingltonSet_Test_Impl ", AsyncPsi_SingltonSet_Test_Impl);
		run("AsyncPsi_EmptrySet_Test_Impl   ", AsyncPsi_EmptrySet_Test_Impl  );
		run("Psi_FullSet_Test_Impl          ", Psi_FullSet_Test_Impl);
		run("Psi_SingltonSet_Test_Impl      ", Psi_SingltonSet_Test_Impl);
		run("Psi_EmptrySet_Test_Impl        ", Psi_EmptrySet_Test_Impl   );
}
void HalfGtGarbledCircuit_all()
{
	Lg::out << Lg::endl;
	run("HalfGtGC_BasicGates           ", HalfGtGC_BasicGates_Test_Impl);
	run("HalfGtGC_BitAdder             ", HalfGtGC_BitAdder_Test_Impl);
	run("HalfGtGC_BitAdder_Validate    ", HalfGtGC_BitAdder_Validate_Test_Impl);
}

void KProbe_all()
{
	Lg::out << Lg::endl;

#ifdef ENCODABLE_KRPOBE
	run("KProbe_BitVector              ", KProbe_BitVector_Test_Impl);
	run("KProbe_Labels                 ", KProbe_Labels_Test_Impl);
	run("KProbe_ZeroLabels             ", KProbe_ZeroLabels_Test_Impl);
#endif

	run("KProbe_Build                  ", KProbe_Build_Test_Impl);
	run("KProbe_SaveLoad               ", KProbe_SaveLoad_Test_Impl);
	run("KProbe_XORTransitive          ", KProbe_XORTransitive_Test_Impl);
}


//void NetWork_all()
//{
//	Lg::out << Lg::endl;
//	run("Network_Connect1              ", Network_Connect1_Local_Test_Impl);
//	run("Network_ConnectMany           ", Network_ConnectMany_Local_Test_Impl);
//	run("Network_CrossConnect          ", Network_CrossConnect_Test_Impl);
//}

void OT_all()
{
	Lg::out << Lg::endl;
	run("OTExt_100Receive              ", OTExt_100Receive_Test_Impl);
}


void NetWork_all()
{
	Lg::out << Lg::endl;
	run("BtNetwork_Connect1_Boost_Test        ", BtNetwork_Connect1_Boost_Test);
	run("BtNetwork_OneMegabyteSend_Boost_Test ", BtNetwork_OneMegabyteSend_Boost_Test);
	run("BtNetwork_ConnectMany_Boost_Test     ", BtNetwork_ConnectMany_Boost_Test);
	run("BtNetwork_CrossConnect_Test          ", BtNetwork_CrossConnect_Test);
	run("BtNetwork_ManyEndpoints_Test         ", BtNetwork_ManyEndpoints_Test);

}




void runAll()
{
	//AES128_all();
	//Circuit_all();
	//CircuitPackage_all();
	//DualExActor_all();
	//HalfGtGarbledCircuit_all();
	//KProbe_all();
	PSI_all();
	//NetWork_all();
	//OT_all();
}
