#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/BtEndpoint.h"
#include "signalHandle.h"

#include <vector>
#include <thread>
#include "boost/asio.hpp"
//#include "boost/filesystem.hpp"
#include <functional>
#include <cassert>
#include <chrono>
#include <fstream>

#include "Common.h"
//#include "OT/OTExtension.h"
#include "cryptoTools/Common/Exceptions.h"
#include "cryptoTools/Common/Defines.h"
#include "Circuit/Circuit.h"
#include "DualEx/DualExActor.h"
#include "cryptoTools/Common/Log.h"
#include "DebugCircuits.h"

#include <stdlib.h>
#include <sstream>
#include <fstream>
#include <iostream> 

#include "ezOptionParser.h" 

#include "UnitTests.h"

using namespace ez;
using namespace osuCrypto;

void Eval(Circuit& cir, u64 numExe, u64 bucketSize, u64 numOpened, u64 numConcurrentSetups, u64 numConcurrentEvals, u64 numThreadsPerEval,
    bool v, 
    bool timefiles,
    Timer& timer);


void pingTest(Endpoint& netMgr, Role role)
{
    u64 count = 100;
    std::array<u8, 131072> oneMB;

    Timer timer;
    auto& chl = netMgr.addChannel("ntSend");
    ByteStream buff;
    if (role)
    {
        auto send = timer.setTimePoint("ping sent");
        for (u64 i = 0; i < count; ++i)
        {
            chl.asyncSend("c", 1);
            chl.recv(buff);
            if (buff.size() != 1)
            {
                std::cout << std::string((char*)buff.data(), (char*)buff.data() + buff.size()) << std::endl;
                throw std::runtime_error("");
            }
        }
        chl.asyncSend("r", 1);

        auto recv = timer.setTimePoint("ping recv");

        auto ping = std::chrono::duration_cast<std::chrono::microseconds>(recv - send).count() / count;

        std::cout << "ping " << ping << " us" << std::endl;

        send = timer.setTimePoint("");
        chl.asyncSend(oneMB.data(), oneMB.size());
        chl.recv(buff);
        recv = timer.setTimePoint("");
        if (buff.size() != 1) throw std::runtime_error("");

        double time = static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(recv - send).count() - ping);

        chl.recv(buff);
        chl.asyncSend("r", 1);
        if (buff.size() != oneMB.size()) throw std::runtime_error("");


        std::cout << (1000000 / time) << " Mbps" << std::endl;
    }
    else
    {
        chl.recv(buff);

        auto send = timer.setTimePoint("ping sent");
        for (u64 i = 0; i < count; ++i)
        {
            chl.asyncSend("r", 1);
            chl.recv(buff);
            if (buff.size() != 1) throw std::runtime_error("");

        }

        auto recv = timer.setTimePoint("ping recv");

        auto ping = std::chrono::duration_cast<std::chrono::microseconds>(recv - send).count() / count;
        std::cout << "ping " << ping << " us" << std::endl;

        chl.recv(buff);
        chl.asyncSend("r", 1);
        if (buff.size() != oneMB.size()) throw std::runtime_error("");


        send = timer.setTimePoint("");
        chl.asyncSend(oneMB.data(), oneMB.size());
        chl.recv(buff);
        recv = timer.setTimePoint("");
        if (buff.size() != 1) throw std::runtime_error("");

        double time = static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(recv - send).count() - ping);

        std::cout << (1000000 / time) << " Mbps" << std::endl;

    }

    chl.close();
}

void commandLineMain(int argc, const char** argv)
{
    block b;
    Timer timer;

    AES key(ZeroBlock);
    key.ecbEncBlock(b, b);



    ezOptionParser opt;

    opt.add(
        "./",
        0,
        1,
        0,
        "run unit tests, using this as the directory for unit tests data folder",
        "-u",
        "--unittest");

    opt.add(
        "", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "This player's role, 0/1 (required).", // Help description.
        "-r", // Flag token.
        "--role" // Flag token.
    );

    opt.add(
        "1212", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Base port number used by Server.x (default: 5000).", // Help description.
        "-p", // Flag token.
        "--portnum" // Flag token.
    );

    opt.add(
        "localhost", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Host name that Server.x is running on (default: localhost).", // Help description.
        "-h", // Flag token.
        "--hostname" // Flag token.
    );

    opt.add(
        "128",
        0,
        1,
        0,
        "Number of executions to run (default: 128).",
        "-n",
        "--nExec"
    );

    opt.add(
        "4",
        0,
        1,
        0,
        "bucket size (default: 4).",
        "-b",
        "--bcktSize"
    );


    opt.add(
        "0",
        0,
        1,
        0,
        "Number of opened circuits(default: 100).",
        "-o",
        "--open"
    );


    opt.add(
        "./circuits/AES-non-expanded.txt",
        0,
        1,
        0,
        "Circuit description file",
        "-f",
        "--file");

    opt.add(
        "",
        0,
        0,
        0,
        "perform network ping at the start",
        "-i",
        "--ping");

    opt.add(
        "4",
        0,
        1,
        0,
        "number of concurrent setup phases. (4x threads) and defaults to 4",
        "-s",
        "--setupConcurrently");

    opt.add(
        "1",
        0,
        1,
        0,
        "denotes the number of concurrent evaluations. defaults to 1 (sequential)",
        "-e",
        "--evalConcurrently");

    opt.add(
        "",
        0,
        1,
        0,
        "denotes the number of circuit threads per evaluations. defaults to bucket size",
        "-c",
        "--circuitThreads");

    opt.add(
        "40",
        0,
        1,
        0,
        "statistical security param",
        "-k",
        "--statisticalK");

    opt.add(
        "0",
        0,
        1,
        0,
        "Turn on extra printing",
        "-v",
        "--verbose");


    opt.add(
        "0",
        0,
        1,
        0,
        "Output additional timing information to text files.",
        "-l",
        "--timefiles");
    opt.parse(argc, argv);

    std::string hostname, file;
    u64 portnum, numExec, bucketSize, numOpened, numConcurrentSetups, numConcurrentEvals, numThreadsPerEval, psiSecParam;
    Role role;
    int temp, verbose, timefiles;

    opt.get("-r")->getInt(temp); role = (Role)temp;
    opt.get("-n")->getInt(temp); numExec = static_cast<u64>(temp);
    opt.get("-b")->getInt(temp); bucketSize = static_cast<u64>(temp);
    opt.get("-o")->getInt(temp); numOpened = static_cast<u64>(temp);
    opt.get("-p")->getInt(temp); portnum = static_cast<u64>(temp);
    opt.get("-s")->getInt(temp); numConcurrentSetups = static_cast<u64>(temp);
    opt.get("-e")->getInt(temp); numConcurrentEvals = static_cast<u64>(temp);
    opt.get("-k")->getInt(temp); psiSecParam = static_cast<u64>(temp);
    opt.get("-h")->getString(hostname);
    opt.get("-f")->getString(file);
    verbose = opt.get("-v")->isSet;
    timefiles = opt.get("-l")->isSet;

    if (opt.get("-c")->isSet)
    {
        opt.get("-c")->getInt(temp); numThreadsPerEval = static_cast<u64>(temp);
    }
    else
    {
        numThreadsPerEval = bucketSize;
    }

    std::cout << "role: " << (int)role
        << "  numExe:" << numExec
        << "  bucketSize:" << bucketSize
        << "  numOpen:" << numOpened
        << "  ConcurrentSetups:" << numConcurrentSetups
        << "  ConcurrentEvals:" << numConcurrentEvals
        << "  numThreadsPerEval:" << numThreadsPerEval << std::endl;


    if (opt.get("-u")->isSet)
    {
        opt.get("-u")->getString(testData);
        runAll();
        return;
    }
    Circuit cir;


    if (verbose) std::cout << "reading circuit: " << file;


    std::fstream fStrm(file);
    if (fStrm.is_open() == false)
    {
        //boost::filesystem::path getcwd(boost::filesystem::current_path());
        //std::cout << "Current path is: " << getcwd << std::endl;
        std::cout << "\nfailed to open circuit file: " << file << std::endl;

        throw std::runtime_error("");
    }


    cir.readBris(fStrm);

    if (verbose) std::cout << std::endl;

    if (cir.Inputs()[0] * cir.Inputs()[1] == 0)
    {
        std::cout << " **** circuit has one party input. changing circuit to two party by XOR splitting the input. **** " << std::endl;

        cir.xorShareInputs();
    }


    if (verbose)
    {
        std::cout << "circuit inputs " << cir.Inputs()[0] << " " << cir.Inputs()[1] << std::endl;
        std::cout << "circuit num gates " << cir.Gates().size() << std::endl;
        std::cout << "circuit num AND gates " << cir.NonXorGateCount() << std::endl;
        std::cout << "circuit num outputs " << cir.OutputCount() << std::endl;
    }


    if (opt.get("-r")->isSet == false)
    {
        if(verbose) std::cout << "\n                Single Terminal Eval\n" << std::endl;

        Eval(
            cir, 
            numExec, 
            bucketSize, 
            numOpened,
            numConcurrentSetups,
            numConcurrentEvals,
            numThreadsPerEval,
            verbose,
            timefiles,
            timer);

        return;
    }


    BtIOService ios(0);
    BtEndpoint netMgr(ios, hostname, portnum, role, "ss");


    if (verbose)
    {
        std::cout << "Connecting..." ;
        auto fu = std::async([&]() {netMgr.addChannel("___testchannel____").close(); });
        while (fu.wait_for(std::chrono::seconds(1)) == std::future_status::timeout) std::cout << ".";
        std::cout << std::endl;
    }

    if (opt.get("-i")->isSet)
    {
        pingTest(netMgr, role);
    }


    DualExActor actor(cir, role, numExec, bucketSize, numOpened, psiSecParam, netMgr);
    actor.PRINT_EVAL_TIMES = actor.PRINT_SETUP_TIMES = timefiles;

    PRNG prng(_mm_set_epi64x(0, role));

    std::cout << "Initializing..." << std::endl;

    auto initStart = timer.setTimePoint("Init Start");

    actor.init(prng, numConcurrentSetups, numConcurrentEvals, numThreadsPerEval, timer);

    std::cout << "exec..." << std::endl;

    // do one without the timing to sync the two parties...
    BitVector input(cir.Inputs()[role]);

    u64 sleepTime = 100;
    auto initFinish = timer.setTimePoint("init done (sleep for 100 ms)");
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
    //actor.execute(0, input, timer);
    //--numExec;

    auto evalStart = timer.setTimePoint("Exec Start");

    std::vector<u64> times(numExec);
    std::vector<std::thread> evalThreads(numConcurrentEvals);
    int iii = 0;

    for (u64 j = 0; j < numConcurrentEvals; ++j)
    {

        block seed = prng.get<block>();
        evalThreads[j] = std::thread([&, j, seed]() {

            //std::cout << "main " << j << " / " << numConcurrentEvals << std::endl;

            Timer t2;
            auto last = t2.setTimePoint("");
            PRNG prng(seed);
            for (u64 i = j; i < static_cast<u64>(numExec); i += numConcurrentEvals)
            {

                //std::this_thread::sleep_for(std::chrono::mi(j));

                //std::cout << "Exec" << i << std::endl;
                ++iii;
                actor.execute(i, prng, input, timer);

                auto now = t2.setTimePoint("");
                auto diff = now - last;
                times[i] = std::chrono::duration_cast<std::chrono::microseconds>(diff).count();
                //if (times[i] < min) min = times[i];

                last = now;
            }

            //std::cout << "main " << j << " done"<<std::endl;

        });
    }


    auto finished = timer.setTimePoint("Exec Finished");
    for (u64 j = 0; j < numConcurrentEvals; ++j)
    {
        evalThreads[j].join();
    }
    u64 min = 9999999;// initFinish - initStart;
    u64 onlineTotal = 0;

    std::fstream timeFile;


    timeFile.open("./timeFile.txt", std::ios::trunc | std::ios::out);
    timeFile << "main " << std::endl;

    for (u64 i = numConcurrentEvals; i < static_cast<u64>(numExec); i++)
    {
        onlineTotal += times[i];
        if (times[i] < min) min = times[i];

        timeFile << times[i] << std::endl;
    }
    auto offlineTotal = std::chrono::duration_cast<std::chrono::microseconds>(initFinish - initStart).count();

    actor.printTimes("./timeFile");

    //std::cout << "initTime " << std::chrono::duration_cast<std::chrono::milliseconds>(initFinish - initStart).count() << " ms" << std::endl;
    std::cout << "Done. " << std::endl << std::endl;
    std::cout << "total offline   = " << offlineTotal / 1000.0 << " ms" << std::endl;
    std::cout << "total online    = " << onlineTotal / 1000.0 << " ms" << std::endl;
    std::cout << "offline / eval  = " << offlineTotal / numExec / 1000.0 << " ms" << std::endl;
    std::cout << "online / eval   = " << onlineTotal / numExec / 1000.0 << " ms" << std::endl;

    if (verbose)
    {

        std::cout << "min online time = " << min / 1000.0 << " ms" << std::endl;
        std::cout << std::endl << std::endl << "detailed time:  Label    totalTime(ms)   difference(us) " << std::endl;
        std::cout << timer << std::endl << std::endl << "Communication info:\n";


        std::cout << "Input request size         " << cir.Inputs()[role] / 8 << " bytes" << std::endl;
        std::cout << "My input size              " << cir.Inputs()[role] * sizeof(block) * bucketSize << " bytes" << std::endl;
        std::cout << "Their input size           " << cir.Inputs()[1 ^ role] * sizeof(block) * bucketSize << " bytes" << std::endl;

#ifdef ASYNC_PSI
        std::cout << "Async PSI commit send size " << bucketSize * psiSecParam / 8 << " bytes" << std::endl;
        std::cout << "Async PSI commit recv size " << bucketSize * psiSecParam / 8 << " bytes" << std::endl;
        std::cout << "Translation open size      " << sizeof(block) << " bytes" << std::endl;
        std::cout << "Async PSI Open size        " << sizeof(block) * psiSecParam *  bucketSize * bucketSize << " bytes" << std::endl << std::endl;
#else
        std::cout << "PSI OT permute size        " << bucketSize * psiSecParam / 8 << " bytes" << std::endl;
        std::cout << "PSI sender commit size     " << bucketSize * bucketSize * sizeof(block) << " bytes" << std::endl;
        std::cout << "Translation open size      " << sizeof(block) << " bytes" << std::endl;
        std::cout << "Sync PSI Open size         " << sizeof(block) *  bucketSize * bucketSize << " bytes" << std::endl << std::endl;
#endif
    }

    //std::cout << "total " << std::chrono::duration_cast<std::chrono::milliseconds>(finished - initStart).count() - sleepTime << " ms" << std::endl;

    actor.close();

    netMgr.stop();
    ios.stop();
    return;
}


#include "Common.h"

void Eval(
    Circuit& cir,
    u64 numExe,
    u64 bucketSize,
    u64 numOpened,
    u64 numConcurrentSetups,
    u64 numConcurrentEvals,
    u64 numThreadsPerEval,
    bool verbose,
    bool timefiles,
    Timer& timer)
{
    u64 psiSecParam = 40;

    setThreadName("Actor1");




    BtIOService ios(0);
    BtEndpoint netMgr0(ios, "127.0.0.1", 1212, true, "ss");
    //NetworkManager netMgr0("127.0.0.1", 1212, 4, true);

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
    PRNG prng1(prng0.get<block>());


    BitVector expected(5);
    *expected.data() = 5;

    auto thrd = std::thread([&]() {
        setThreadName("Actor0");

        DualExActor actor0(cir, Role::First, numExe, bucketSize, numOpened, psiSecParam, netMgr0);
        actor0.PRINT_EVAL_TIMES = actor0.PRINT_SETUP_TIMES = timefiles;

        Timer timer;
        actor0.init(prng0, numConcurrentSetups, numConcurrentEvals, numThreadsPerEval, timer);

        BitVector input0(cir.Inputs()[0]);
        *input0.data() = 2;

        std::vector<std::thread> evalThreads(numConcurrentEvals);

        for (u64 j = 0; j < numConcurrentEvals; ++j)
        {

            block seed = prng0.get<block>();
            evalThreads[j] = std::thread([&, j, seed]() {
                Timer t2;
                PRNG prng(seed);
                for (u64 i = j; i < static_cast<u64>(numExe); i += numConcurrentEvals)
                {
                    actor0.execute(i, prng, input0, t2);
                }
            });
        }

        for (auto& thrd : evalThreads)
            thrd.join();
    });


    //BtIOService ios(0);
    BtEndpoint netMgr1(ios, "127.0.0.1", 1212, false, "ss");

    DualExActor actor1(cir, Role::Second, numExe, bucketSize, numOpened, psiSecParam, netMgr1);
    actor1.PRINT_EVAL_TIMES = actor1.PRINT_SETUP_TIMES = timefiles;

    std::cout << "Initializing..." << std::endl;

    auto initStart = timer.setTimePoint("initStart");

    actor1.init(prng1, numConcurrentSetups, numConcurrentEvals, numThreadsPerEval, timer);

    auto initFinish = timer.setTimePoint("initFinish");

    //std::this_thread::sleep_for(std::chrono::seconds(1));

    BitVector input1(cir.Inputs()[1]);
    //*input1.data() = 3;

    std::cout << "exec start..." << std::endl;


    auto min = initFinish - initStart;
    std::vector<std::thread> evalThreads(numConcurrentEvals);

    for (u64 j = 0; j < numConcurrentEvals; ++j)
    {
        block seed = prng1.get<block>();
        evalThreads[j] = std::thread([&, j, seed]() {
            Timer t2;
            auto last = t2.setTimePoint("");;
            PRNG prng(seed);
            for (u64 i = j; i < static_cast<u64>(numExe); i += numConcurrentEvals)
            {
                actor1.execute(i, prng, input1, t2);

                auto now = t2.setTimePoint("");
                auto diff = now - last;
                if (diff < min) min = diff;

                last = now;
            }
        });
    }

    for (auto& thrd : evalThreads)
        thrd.join();

    auto finished = timer.setTimePoint("finished");

    thrd.join();

    std::cout << "Done. " << std::endl << std::endl;
    std::cout << "total offline   = " << std::chrono::duration_cast<std::chrono::microseconds>(initFinish - initStart).count() / 1000.0 << " ms" << std::endl;
    std::cout << "total online    = " << std::chrono::duration_cast<std::chrono::microseconds>(finished - initFinish).count() / 1000.0 << " ms" << std::endl;
    std::cout << "time/eval       = " << std::chrono::duration_cast<std::chrono::microseconds>(finished - initFinish).count() / numExe / 1000.0 << " ms" << std::endl;
    std::cout << "min eval time   = " << std::chrono::duration_cast<std::chrono::microseconds>(min).count() / 1000.0 << " ms" << std::endl << std::endl << std::endl;

    if (verbose)
    {

        std::cout << std::endl << std::endl << "detailed time:  Label    totalTime(ms)   difference(us) " << std::endl;
        std::cout << timer << std::endl << std::endl << "Communication info:\n";


        std::cout << "Input request size (role = 0)  " << cir.Inputs()[0] / 8 << " bytes" << std::endl;
        std::cout << "My input size                  " << cir.Inputs()[0] * sizeof(block) * bucketSize << " bytes" << std::endl;
        std::cout << "Their input size               " << cir.Inputs()[1] * sizeof(block) * bucketSize << " bytes" << std::endl;

#ifdef ASYNC_PSI
        std::cout << "Async PSI commit send size     " << bucketSize * psiSecParam / 8 << " bytes" << std::endl;
        std::cout << "Async PSI commit recv size     " << bucketSize * psiSecParam / 8 << " bytes" << std::endl;
        std::cout << "Translation open size          " << sizeof(block) << " bytes" << std::endl;
        std::cout << "Async PSI Open size            " << sizeof(block) * psiSecParam *  bucketSize * bucketSize << " bytes" << std::endl << std::endl;
#else                                               
        std::cout << "PSI OT permute size            " << bucketSize * psiSecParam / 8 << " bytes" << std::endl;
        std::cout << "PSI sender commit size         " << bucketSize * bucketSize * sizeof(block) << " bytes" << std::endl;
        std::cout << "Translation open size          " << sizeof(block) << " bytes" << std::endl;
        std::cout << "Sync PSI Open size             " << sizeof(block) *  bucketSize * bucketSize << " bytes" << std::endl << std::endl;
#endif
    }

    actor1.close();

    netMgr0.stop();
    netMgr1.stop();

    ios.stop();
}


int main(int argc, const char** argv)
{
    backtraceHook();

    //Eval();
    commandLineMain(argc, argv);
    /*
    #ifdef _MSC_VER
        testData = "../..";
    #else
        testData = "/mnt/hgfs/osuCrypto";
    #endif



        runAll();;

        std::cout << "DONE___" << std::endl;*/
}
