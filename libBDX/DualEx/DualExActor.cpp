#include "cryptoTools/Common/Timer.h"
#include "DualExActor.h"
#include <future>
#include "cryptoTools/Crypto/Commit.h"
#include <algorithm>
#include "PSI/PSIReceiver.h"
#include "PSI/PSISender.h"
#include "cryptoTools/Common/Log.h"
#include <mutex>
#include <fstream>
#include "cryptoTools/Network/Endpoint.h"
#include "DualEx/Bucket.h"
#include "libOTe/Base/naor-pinkas.h"

#define PARALLEL_PSI 

namespace osuCrypto
{

    void GetRandSubset(u64 subsetSize, u64 setSize, PRNG& prng, std::vector<u64>& subset, std::vector<u64>& difference)
    {
        subset.clear();
        difference.clear();
        subset.resize(subsetSize);
        difference.resize(setSize - subsetSize);

        for (u64 i = 0; i < subsetSize; ++i)
            subset[i] = i;

        if (subsetSize)
        {
            for (u64 i = subsetSize, j = 0; i < setSize; ++i, ++j)
            {
                difference[j] = i;

                u64 randIdx = prng.get<u64>() % i;
                if (randIdx < subsetSize)
                    std::swap(subset[randIdx], difference[j]);
            }
        }
        else
        {
            for (u64 i = 0; i < setSize; ++i)
                difference[i] = i;
        }
    }


    DualExActor::DualExActor(
        const Circuit& cir,
        const Role role,
        const u64 numExes,
        const u64 bucketSize,
        const u64 numOpened,
        const u64 psiSecParam,
        Endpoint & netMgr)
        :
        mCircuit(cir),
        mRole(role),
        mNetMgr(netMgr),
        mNumExe(numExes),
        mBucketSize(bucketSize),
        mNumOpened(numOpened),
        mNumCircuits(numOpened + bucketSize * numExes),
        mPsiSecParam(psiSecParam),
        //mEvalIdx(0),
        PRINT_SETUP_TIMES(0), 
        PRINT_EVAL_TIMES(0),
        mCnCCommitRecvDone(false),
        mBuckets(numExes),
        mOnlineFuture(mOnlineProm.get_future())
    {
        if (cir.Inputs()[0] == 0 || cir.Inputs()[1] == 0)
            throw std::runtime_error("There are better protocols for such things...");
    }


    void DualExActor::getRecvOTs(block prngSeed, u64 numInit, u64 numOTExtPer)
    {

        PRNG prng(prngSeed);
        auto& chl = mNetMgr.addChannel("OTRecv", "OTSend");
        NaorPinkas baseOTs;// (chl, OTRole::Sender);

        std::array<std::array < block, 2>, gOtExtBaseOtCount> baseOTsSender_inputs;
        baseOTs.send(baseOTsSender_inputs, prng, chl);

        std::vector<std::thread> thrds(numInit - 1);
        //std::vector<PRNG> prngs(numInit - 1);

        std::vector<std::array< std::array<block, 2>, gOtExtBaseOtCount>> bases(numInit);
        std::array< std::array<PRNG, 2>, gOtExtBaseOtCount> extenders;

        for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
        {
            extenders[i][0].SetSeed(baseOTsSender_inputs[i][0]);
            extenders[i][1].SetSeed(baseOTsSender_inputs[i][1]);
        }

        for (u64 t = 0; t < thrds.size(); ++t)
        {
            //prngs[t].SetSeed(prng.get<block>());

            auto& idx = mOTRecvDoneIdx[t];
            assert(idx == 0);

            for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
            {
                bases[t][i][0] = extenders[i][0].get<block>();
                bases[t][i][1] = extenders[i][1].get<block>();
            }
            block seed = prng.get<block>();

            thrds[t] = std::thread([&, t, seed]() {
                PRNG prng2(seed);
                Channel& chl = mNetMgr.addChannel("OTRecv" + ToString(t), "OTSend" + ToString(t));
                mOTRecv[t].Extend(bases[t], numOTExtPer, prng2, chl, mOTRecvDoneIdx[t]);
                chl.close();
            });
        }

        for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
        {
            bases[numInit - 1][i][0] = extenders[i][0].get<block>();
            bases[numInit - 1][i][1] = extenders[i][1].get<block>();
        }
        mOTRecv[numInit - 1].Extend(bases[numInit - 1], numOTExtPer, prng, chl, mOTRecvDoneIdx[numInit - 1]);

        chl.close();

        for (auto& thrd : thrds)
            thrd.join();
    }

    void DualExActor::getSendOTs(block prngSeed, u64 numInit, u64 numOTExtPer)
    {
        auto& chl = mNetMgr.addChannel("OTSend", "OTRecv");
        NaorPinkas baseOTs;// (chl, OTRole::Receiver);
        PRNG prng(prngSeed);

        BitVector baseOTsReceiver_inputs(gOtExtBaseOtCount);
        baseOTsReceiver_inputs.randomize(prng);
        std::array < block, gOtExtBaseOtCount> baseOTsReceiver_outputs;
        baseOTs.receive(baseOTsReceiver_inputs, baseOTsReceiver_outputs, prng, chl);

        std::vector<std::thread> thrds(numInit - 1);
        //std::vector<PRNG> prngs(numInit - 1);

        std::vector<std::array< block, gOtExtBaseOtCount>> bases(numInit);
        std::array<PRNG, gOtExtBaseOtCount> extenders;

        for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
        {
            extenders[i].SetSeed(baseOTsReceiver_outputs[i]);
        }

        for (u64 t = 0; t < thrds.size(); ++t)
        {
            auto& idx = mOTSendDoneIdx[t];
            assert(idx == 0);
            //prngs[t].SetSeed(prng.get<block>());
            block seed = prng.get<block>();

            for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
            {
                bases[t][i] = extenders[i].get<block>();
            }
            thrds[t] = std::thread([&, t, seed]() {
                PRNG prng2(seed);
                Channel& chl = mNetMgr.addChannel("OTSend" + ToString(t), "OTRecv" + ToString(t));
                mOTSend[t].Extend(bases[t], baseOTsReceiver_inputs, numOTExtPer, prng2, chl, mOTSendDoneIdx[t]);
                chl.close();
            });
        }

        for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
        {
            bases[numInit - 1][i] = extenders[i].get<block>();
        }
        mOTSend[numInit - 1].Extend(bases[numInit - 1], baseOTsReceiver_inputs, numOTExtPer, prng, chl, mOTSendDoneIdx[numInit - 1]);
        chl.close();

        for (auto& thrd : thrds)
            thrd.join();
    }


    void DualExActor::close()
    {
        for (auto recvChl : mRecvMainChls)
            recvChl->close();
        mRecvMainChls.clear();

        for (auto& sendThrd : mSendMainThreads)
            sendThrd.join();
        mSendMainThreads.clear();

        for (auto& sendThrd : mSendSubThreads)
            sendThrd.join();
        mSendSubThreads.clear();

        for (auto sendChl : mSendSubChls)
            sendChl->close();
        mSendSubChls.clear();

        for (auto& thrd : mEvalThreads)
            thrd.join();
        mEvalThreads.clear();

        for (auto& recvSubThrd : mRecvSubChls)
            recvSubThrd->close();
        mRecvSubChls.clear();
    }

    /// This function starts the process of generating and receiving circuits and related things. It will spin off
    /// numParallelInit * 4 threads. Two for generating and receiving OTs, Two for generating and receiving Circuits.
    /// numParallelEval determines how many parallel evaluations can be performed at once. default it 1.
    /// numThreadsPerEval determines how many threads should be used for each evaluation. Typically bucket size... 
    void DualExActor::init(PRNG& prng, u64 numParallelInit, u64 numParallelEval, u64 numThreadsPerEval, Timer& timer)
    {
        Channel& chl = mNetMgr.addChannel("init");

        // send cut n choose commitments 
        block myCnCSeed = prng.get<block>();
        auto CnCom = Commit(myCnCSeed);
        chl.asyncSend(&CnCom, sizeof(Commit));


        // compute my cut n choose sets
        PRNG mySetsPrng(myCnCSeed);
        GetRandSubset(mNumOpened, mNumCircuits, mySetsPrng, mMyCnCSets[0], mMyCnCSets[1]);

        // set up the k-probe resistant matrices in both directions
        u64 kProbeSecParam = mPsiSecParam;
        block seeds[2] = { _mm_set_epi64x(23456543, 3456544765) ,_mm_set_epi64x(654387654567, 6789544) };
        PRNG myKPRrobePrng(seeds[mRole]), theirKProbePrng(seeds[1 - mRole]);

        mMyKProbe.loadOrBuild(mCircuit.Inputs()[mRole], kProbeSecParam, myKPRrobePrng);
        mTheirKProbe.loadOrBuild(mCircuit.Inputs()[1 - mRole], kProbeSecParam, theirKProbePrng);

        // Lets Send over the parameters we are using
        std::unique_ptr<ByteStream> paramBuff(new ByteStream());
        paramBuff->append((u8*)&numParallelInit, sizeof(numParallelInit));
        paramBuff->append((u8*)&numParallelEval, sizeof(numParallelEval));
        paramBuff->append((u8*)&numThreadsPerEval, sizeof(numThreadsPerEval));
        paramBuff->append((u8*)&mNumExe, sizeof(mNumExe));
        paramBuff->append((u8*)&mBucketSize, sizeof(mBucketSize));
        paramBuff->append((u8*)&mNumCircuits, sizeof(mNumCircuits));
        paramBuff->append((u8*)&mPsiSecParam, sizeof(mPsiSecParam));
        paramBuff->append((u8*)&mMyKProbe.mSignature, sizeof(u64));
        paramBuff->append((u8*)&mTheirKProbe.mSignature, sizeof(u64));
        chl.asyncSend(std::move(paramBuff));

        // Compute the required size of the index array. Used for many things when doing AES fixed key or seed based PRNG.
        u64 size = std::max(std::max(std::max(mMyKProbe.encodingSize(), mTheirKProbe.encodingSize()), mCircuit.WireCount()), mCircuit.Gates().size() * 2);
        // Generate the Index Array, simply as 1,2,3,4,..., size
        mIndexArray.resize(size);
        for (u64 i = 0; i < size; ++i)
            mIndexArray[i] = _mm_set_epi64x(0, i);

        // the init phase will have 4 concurrent pipes that things will be divided between...
        mNumInitThreads = std::min((u64)numParallelInit, mNumExe);

#ifdef ASYNC_PSI
        u64 otsPerPSI = AsyncPsiSender::PsiOTCount(mBucketSize, mPsiSecParam);
#else
        u64 otsPerPSI = PsiSender::PsiOTCount(mBucketSize, mPsiSecParam);
#endif // ASYNC_PSI

        // compute how many OTs each pipe will need
        u64 numSendOTsPer = mTheirKProbe.encodingSize() * (mNumCircuits + mNumInitThreads - 1) / mNumInitThreads
            + otsPerPSI * (mNumExe + mNumInitThreads - 1) / mNumInitThreads;
        u64 numRecvOTsPer = mMyKProbe.encodingSize() * (mNumCircuits + mNumInitThreads - 1) / mNumInitThreads
            + otsPerPSI * (mNumExe + mNumInitThreads - 1) / mNumInitThreads;

        // each one of these will hold numSendOTsPer OTs and will be used by the garbling threads
        mOTRecv.resize(mNumInitThreads);
        mOTSend.resize(mNumInitThreads);

        // these are used to synchronize the OT generator threads with the garbling threads.
        mOTSendDoneIdx.reset(new std::atomic<u64>[mNumInitThreads]());
        mOTRecvDoneIdx.reset(new std::atomic<u64>[mNumInitThreads]());
        for (u64 i = 0; i < mNumInitThreads; ++i) { mOTSendDoneIdx[i] = mOTRecvDoneIdx[i] = 0; }

        // spin off two threads that will start generating the OTs, these will fork into numInitThreads threads
        block sendOTSeed(prng.get<block>());
        block recvOTSeed(prng.get<block>());

        // Spin off the OT threads. There two threads will generate mNumInitThreads-1 other threads, all doing OTs
        mOTSendThrd = std::thread([&, sendOTSeed]() { getSendOTs(sendOTSeed, mNumInitThreads, numSendOTsPer); });
        mOTRecvThrd = std::thread([&, recvOTSeed]() { getRecvOTs(recvOTSeed, mNumInitThreads, numRecvOTsPer); });

        //mOTSendThrd.join();
        //mOTRecvThrd.join();
        // allocate threads for generating and receiving circuits
        std::vector<std::thread> sendThrds(mNumInitThreads);
        std::vector<std::thread> recvThrds(mNumInitThreads);

        // allocate circuits
        mMyCircuits.resize(mNumCircuits);
        mTheirCircuits.resize(mNumCircuits);

        // set up some synchronizing vars for when we have received all their circuits
        mCirRecvProm.resize(mNumInitThreads);
        mCirRecvFutr.resize(mNumInitThreads);
        for (u64 i = 0; i < mNumInitThreads; ++i) mCirRecvFutr[i] = mCirRecvProm[i].get_future().share();

        // set up a shared future for when we know their cut n choose selection
        mTheirSetsFutr = mOpenEvalSetsProm.get_future().share();

        // get their cut n choose commitment
        Commit theirCnCCommit;
        chl.recv(&theirCnCCommit, sizeof(Commit));

        // Lets check that the parameters they are using match ours...
        ByteStream paramBuffRecv;
        chl.recv(paramBuffRecv);
        u64 * params = (u64*)paramBuffRecv.data();
        if (*params++ != numParallelInit) { std::cout << "parameter mismatch: numParallelInit us " << numParallelInit << "  them " << *--params << std::endl;  throw std::runtime_error("parameter mismatch: numParallelInit"); }
        if (*params++ != numParallelEval) { std::cout << "parameter mismatch: numParallelEval us " << numParallelEval << "  them " << *--params << std::endl;  throw std::runtime_error("parameter mismatch: numParallelEval"); }
        if (*params++ != numThreadsPerEval) { std::cout << "parameter mismatch: numThreadsPerEval us " << numThreadsPerEval << "  them " << *--params << std::endl;  throw std::runtime_error("parameter mismatch: numThreadsPerEval"); }
        if (*params++ != mNumExe) { std::cout << "parameter mismatch: mNumExe us " << mNumExe << "  them " << *--params << std::endl;  throw std::runtime_error("parameter mismatch: mNumExe"); }
        if (*params++ != mBucketSize) { std::cout << "parameter mismatch: mBucketSize us " << mBucketSize << "  them " << *--params << std::endl;  throw std::runtime_error("parameter mismatch: mBucketSize"); }
        if (*params++ != mNumCircuits) { std::cout << "parameter mismatch: mNumCircuits us " << mNumCircuits << "  them " << *--params << std::endl;  throw std::runtime_error("parameter mismatch: mNumCircuits"); }
        if (*params++ != mPsiSecParam) { std::cout << "parameter mismatch: mPsiSecParam us " << mPsiSecParam << "  them " << *--params << std::endl;  throw std::runtime_error("parameter mismatch: mPsiSecParam"); }
        if (*params++ != mTheirKProbe.mSignature) { std::cout << "parameter mismatch: theirKProbe us " << mTheirKProbe.mSignature << "  them " << *--params << std::endl;  throw std::runtime_error("parameter mismatch: theirKProbe"); }
        if (*params++ != mMyKProbe.mSignature) { std::cout << "parameter mismatch: myKProbe us " << mMyKProbe.mSignature << "  them " << *--params << std::endl;  throw std::runtime_error("parameter mismatch: myKProbe"); }


        // now spin off the send threads what will start sending and receiving circuits
        for (u64 i = 0; i < mNumInitThreads; ++i)
        {
            block sendSeed(prng.get<block>());
            block recvSeed(prng.get<block>());

            sendThrds[i] = std::thread([&, i, sendSeed]()
            {
                setThreadName("initSend_" + std::to_string(mRole) + "_" + std::to_string(i));
                initSend(i, sendSeed, mCirRecvFutr[i], mTheirSetsFutr);
            });
            recvThrds[i] = std::thread([&, i, recvSeed]()
            {
                setThreadName("initRecv_" + std::to_string(mRole) + "_" + std::to_string(i));
                initRecv(i, recvSeed, mCirRecvProm[i], mMyCnCSets);
            });
        }

        // in the mean time, lets init some stuff used in the online phase
        initOnlinePhase(numParallelEval, numThreadsPerEval, prng);

        // wait for us to receive all their circuits
        for (u64 i = 0; i < mNumInitThreads; ++i)
            mCirRecvFutr[i].get();

        timer.setTimePoint("circuits received");

        // decommit the cut n choose selection
        std::unique_ptr<ByteStream> sBuff(new ByteStream());
        sBuff->append(myCnCSeed);
        chl.asyncSend(std::move(sBuff));

        // get their cut n choose decommit 
        block cncSeed;
        chl.recv(&cncSeed, sizeof(block));

        // check the decommit
        if (Commit(cncSeed) != theirCnCCommit)
            throw std::runtime_error(LOCATION);

        // compute the open and eval sets
        PRNG theirSetsPrng(cncSeed);
        GetRandSubset(mNumOpened, mNumCircuits, theirSetsPrng, mTheirCncSets[0], mTheirCncSets[1]);

        // pass the send threads the sets that need to be opened and bucketed
        mOpenEvalSetsProm.set_value(&mTheirCncSets);


        // join all the threads
#ifdef ASYNC_EVAL 
        mOTSendThrd.detach();
        mOTRecvThrd.detach();
        for (u64 i = 0; i < mNumInitThreads; ++i)
        {
            sendThrds[i].detach();
            recvThrds[i].detach();
        }
        timer.setTimePoint("bucketing started");
#else
        mOTSendThrd.join();
        mOTRecvThrd.join();
        for (u64 i = 0; i < mNumInitThreads; ++i)
        {
            sendThrds[i].join();
            recvThrds[i].join();
        }
        timer.setTimePoint("bucketing done");
#endif

        mOnlineProm.set_value();

        chl.close();

    }


    /// This function create the channels and threads that will be used in the online phase. 
    void DualExActor::initOnlinePhase(u64 numParallelEval, u64 numThreadsPerEval, PRNG& prng)
    {

        mLabels.resize(numParallelEval);
        mOutLabels.resize(numParallelEval);
        mSendMainThreads.resize(numParallelEval);

        // set up all the online channels at once (faster unless i implement async connect...)
        //TODO("fix addChannels, There are bugs when too many channels are connected at once. like more than 6.");
        //std::cout << "adding " << (numParallelEval * (1)) << " online channels" << std::endl;

        //std::cout << "added  " << (numParallelEval * (1)) << " online channels" << std::endl;

        mRecvMainChls.resize(numParallelEval);
        //mSendMainChls.resize(numParallelEval);

        numThreadsPerEval = std::min((u64)numThreadsPerEval, mBucketSize);
        mEvalThreads.resize(numThreadsPerEval * numParallelEval);
        mSendSubThreads.resize(numThreadsPerEval * numParallelEval);
        auto evalThrdIter = mEvalThreads.begin();
        auto sendSubThrdIter = mSendSubThreads.begin();
        mTimes.resize(numParallelEval *  numThreadsPerEval);

        // not create the threads used in the online phase.
        for (u64 j = 0; j < numParallelEval; ++j) {

            // allocate buffers for there wire labels will be stored.
            mLabels[j].resize(mBucketSize);

            // this buffer is used to store the complete set of output labels used by the other parties buckets.
            // i.e. then they send the open translation seed, we use this buffer to get the actual labels.
            mOutLabels[j].resize(mCircuit.OutputCount() * 2);

            for (u64 i = 0; i < numThreadsPerEval; ++i)
            {
                // make enough room for all the wire labels.
                mLabels[j][i].resize(mCircuit.WireCount());


                // spin off the thread that will evaluate every i + numThreadsPerEval * j circuit in a bucket for j=0,1,2,...
                block evalSeed = prng.get<block>();
                *evalThrdIter++ = std::thread([this, j, i, numParallelEval, numThreadsPerEval, evalSeed]()
                {
                    // set this threads name. used for debugging in visual studio.
                    setThreadName("EvalThread_" + ToString(mRole) + "_" + ToString(j) + "_" + ToString(i));

                    // create a PRNG used by this thread
                    PRNG prng(evalSeed);

                    // connect to the other party's send input/PSI thread.
                    Channel& chl = mNetMgr.addChannel("onlineEval" + ToString(j) + "_" + ToString(i), "onlineSend" + ToString(j) + "_" + ToString(i));

                    // now start evaluating threads (once the offline is done and inputs are sent).
                    evalThreadLoop(i, numThreadsPerEval, j, numParallelEval, prng, chl);// , mPSIRecvChls[j], mPsiChannelLocks[0][j].get());

                    // all done :)
                    chl.close();
                });

                *sendSubThrdIter++ = std::thread([this, j, i, numParallelEval, numThreadsPerEval]()
                {
                    // set this threads name. used for debugging in visual studio.
                    setThreadName("SendSubThread_" + ToString(mRole) + "_" + ToString(j) + "_" + ToString(i));

                    // connect to the other party's Eval/PSI thread.
                    Channel& chl = mNetMgr.addChannel("onlineSend" + ToString(j) + "_" + ToString(i), "onlineEval" + ToString(j) + "_" + ToString(i));

                    // now wait for inputs and the send the labels and do the PSI.
                    sendCircuitInputLoop(i, numThreadsPerEval, j, numParallelEval, chl);

                    // all done :)
                    chl.close();
                });
            }

            // This thread is used as the place the input correction string is send by the receiving party. 
            // Really it doesn't do too much.
            block seed = prng.get<block>();
            mSendMainThreads[j] = std::thread([this, j, numParallelEval, seed]() {

                // set this threads name. used for debugging in visual studio.
                setThreadName("SendInputLoop_" + ToString(mRole) + "_" + ToString(j));

                // create a PRNG used by this thread
                PRNG prng(seed);
                auto recvName = "onlineMainRecv_" + std::to_string(j);
                auto sendName = "onlineMainSend_" + std::to_string(j);

                Channel* sendChlPtr = nullptr;
                if (mRole)
                {
                    mRecvMainChls[j] = &mNetMgr.addChannel(recvName, sendName);
                    sendChlPtr = &mNetMgr.addChannel(sendName, recvName);
                }
                else
                {
                    sendChlPtr = &mNetMgr.addChannel(sendName, recvName);
                    mRecvMainChls[j] = &mNetMgr.addChannel(recvName, sendName);
                }

                // This function waits for input correction string and then gives it to the sendCircuitInputLoop. 
                // Also is capable of performing the PSI. But normally its performed in parallel and not by this thread.
                sendLoop(j, numParallelEval, *sendChlPtr, prng);

                sendChlPtr->close();
            });

        }

    }

    void DualExActor::initRecv(
        u64 initThrdIdx,
        block prngSeed,
        std::promise<void>& allCirReceived,
        std::array<std::vector<u64>, 2>& cutnChoose)
    {
        // Circuits are split between several threads. This thread will receive the circuits in the following range.
        u64 startIdx = initThrdIdx* mNumCircuits / mNumInitThreads;
        u64 endIdx = (initThrdIdx + 1) * mNumCircuits / mNumInitThreads;
        Timer timer;

        // connect to the other party's circuit generating thread
        Channel& chl = mNetMgr.addChannel("initRecv" + ToString(initThrdIdx), "initSend" + ToString(initThrdIdx));

        // get their circuits, my K-prone input wire label commitments and output label commitments.
        for (u64 i = startIdx; i < endIdx; i++)
        {
            mTheirCircuits[i].init(mCircuit, mMyKProbe, chl, i);
        }



        u64 dummyMessage;
        chl.recv(&dummyMessage, sizeof(u64));
        if (dummyMessage != 0)
            throw std::runtime_error("");

        timer.setTimePoint("Circuits_generated");

        // this index is updated by the OT generating thread and indicates how many completed OT messages there are.
        auto& otDoneIdx = mOTSendDoneIdx[initThrdIdx];

        // this is the index of the OTs that have been used. The functions that use OTs will update it. i.e. initOT, Bucket.initRecv.
        u64 otIdx = 0;

        // get their input wire label commitments.
        for (u64 i = startIdx; i < endIdx; i++)
        {
            while (otDoneIdx < otIdx + mTheirKProbe.encodingSize())std::this_thread::sleep_for(std::chrono::milliseconds(1));

            //u64 tt = otIdx;

            mTheirCircuits[i].initOT(chl, mTheirKProbe, mOTSend[initThrdIdx], otIdx, mCircuit.Inputs()[1 ^ mRole]);

            //if (otIdx != tt + mMyKProbe.encodingSize())
            //	throw std::runtime_error("");
        }

        allCirReceived.set_value();


        chl.recv(&dummyMessage, sizeof(u64));
        if (dummyMessage != 0)
            throw std::runtime_error("");

        timer.setTimePoint("Circuits_OTInit_done");

        // a buffer that is used to unmask the circuit and 
        std::vector<block> blockBuff(std::max(mCircuit.NonXorGateCount() * 2, mTheirKProbe.encodingSize()));

        block theirOTMsgXORSum = ZeroBlock;

        //std::cout << "receive  " + ToString(initThrdIdx) + "  otIdx "  + ToString(otIdx) << std::endl;


        // check the open circuits
        for (u64 cirIdx : cutnChoose[0])
        {
            if (cirIdx >= startIdx && cirIdx < endIdx)
            {
#ifdef ADAPTIVE_SECURE
                //std::cout << "receive " + ToString(initThrdIdx) + " Opening " + ToString(cirIdx) << std::endl;

                mTheirCircuits[cirIdx].open(mCircuit, mTheirKProbe, mMyKProbe, mRole, chl, theirOTMsgXORSum, mIndexArray, blockBuff);
#else
                mTheirCircuits[cirIdx].open(mCircuit, mTheirKProbe, mRole, chl);
#endif
                mTheirCircuits[cirIdx].clear();
            }
        }

        //std::cout << "receive " + ToString(initThrdIdx) + "  Open Done" << std::endl;

        chl.recv(&dummyMessage, sizeof(u64));
        if (dummyMessage != 0)
            throw std::runtime_error("");

        block theirOTMsgProof;
        chl.recv(&theirOTMsgProof, sizeof(block));


        if (neq(theirOTMsgProof, theirOTMsgXORSum))
        {
            std::cout << "receive " + ToString(initThrdIdx) + "  proof my " << theirOTMsgXORSum << " thr " << theirOTMsgProof << std::endl;
            throw std::runtime_error(LOCATION);
        }


        timer.setTimePoint("circuits_opened");
        PRNG prng(prngSeed);

        // we will skip this many circuits between each of out buckets since other threads are bucketing them.
        u64 numSkip = (mNumInitThreads - 1)* mBucketSize;

        // the circuit we should start bucketing with
        auto evalIter = cutnChoose[1].begin() + initThrdIdx * mBucketSize;


#ifdef ASYNC_PSI
        u64 otsPerPSI = AsyncPsiSender::PsiOTCount(mBucketSize, mPsiSecParam);
#else
        u64 otsPerPSI = PsiSender::PsiOTCount(mBucketSize, mPsiSecParam);
#endif // ASYNC_PSI

        // put the remaining circuits into buckets and get their OT aggregation values
        for (u64 bcktIdx = initThrdIdx; bcktIdx < mBuckets.size(); bcktIdx += mNumInitThreads)
        {
            // make sure we have completed the required number of OTs 
            while (otDoneIdx < otIdx + otsPerPSI)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));

            // group together the circuits by having the aggregate OTs. Also set up some stuff used in the online phase.
            mBuckets[bcktIdx].initRecv(mCircuit, chl, mTheirKProbe, mBucketSize, mPsiSecParam, evalIter, mTheirCircuits, mOTSend[initThrdIdx], prng, otIdx, mRole);

            // since we have many threads doing the bucketing, lets skip the circuits that they are bucketing...
            if (bcktIdx + mNumInitThreads < mBuckets.size())
                evalIter += numSkip;
        }


        chl.recv(&dummyMessage, sizeof(u64));
        if (dummyMessage != 0)
            throw std::runtime_error("");

        //std::cout << "receive " + ToString(initThrdIdx) + " bucketing Done" << std::endl;

        // no that the bucketing is done, lets get our K-probe inputs. These are random inputs 
        // done in the offline phase to speed up the online phase. This is done at the end because 
        // it requires the receive OTs to be done. Which are performed by the other threads.
        for (u64 bcktIdx = initThrdIdx; bcktIdx < mBuckets.size(); bcktIdx += mNumInitThreads)
        {
            mBuckets[bcktIdx].initKProbeInputRecv(mCircuit, chl, mMyKProbe, prng, mRole);
        }

        //std::cout << "receive " + ToString(initThrdIdx) + " kprobe Done" << std::endl;

        // all done :)
        chl.close();

        timer.setTimePoint("bucketing_done");
#ifdef ASYNC_PSI
        std::string psi("Async_");
#else
        std::string psi("Sync_");
#endif

        if (PRINT_SETUP_TIMES)
        {
            std::string filename = "timeFile_setup_" + psi + ToString(mNumExe) + "_b" + ToString(mBucketSize) + "_" + ToString(initThrdIdx) + ".txt";
            std::fstream file;
            file.open(filename, std::ios::out);

            if (file.is_open() == false)
                std::cout << "couldnt open file " << filename << std::endl;

            file << timer;
        }


    }

    void DualExActor::initSend(
        u64 initThrdIdx,
        block prngSeed,
        std::shared_future<void>& allCirReceived,
        std::shared_future<std::array<std::vector<u64>, 2>*>& cutnChooseSets)
    {
        PRNG prng(prngSeed);
        Channel& chl = mNetMgr.addChannel("initSend" + ToString(initThrdIdx), "initRecv" + ToString(initThrdIdx));

        u64 startIdx = initThrdIdx* mNumCircuits / mNumInitThreads;
        u64 endIdx = (initThrdIdx + 1) * mNumCircuits / mNumInitThreads;

        // allocate these buffers once. They are used during gabling.
        std::vector<block> wireBuff(mIndexArray.size());
#ifdef ADAPTIVE_SECURE
        std::vector<block> adaptiveSecureTableMasks(mCircuit.NonXorGateCount() * 2);
#endif 

        // generate and send the circuits
        for (u64 i = startIdx; i < endIdx; i++)
        {
#ifdef ADAPTIVE_SECURE
            mMyCircuits[i].init(mCircuit, mRole, prng, chl, i, mTheirKProbe, wireBuff, mIndexArray, adaptiveSecureTableMasks);
#else
            mMyCircuits[i].init(mCircuit, mRole, prng, chl, i, wireBuff);
#endif

        }

        // this message blocks until everything before has been sent. 
        //Temp fixed for sending too much stuff and overflowing the OS TCP buffer
        //TODO("come up with something better inside the network manager");
        u64 dummyMessage = 0;
        chl.send(&dummyMessage, sizeof(dummyMessage));

        u64 otIdx = 0;
        auto& otDoneIdx = mOTRecvDoneIdx[initThrdIdx];
        // generate and send the circuits
        for (u64 i = startIdx; i < endIdx; i++)
        {
            while (otDoneIdx < otIdx + mMyKProbe.encodingSize())std::this_thread::sleep_for(std::chrono::milliseconds(1));

            mMyCircuits[i].initOT(mCircuit, mRole, chl, mMyKProbe, mOTRecv[initThrdIdx], otIdx);
        }


        // this message blocks until everything before has been sent. 
        //Temp fixed for sending too much stuff and overflowing the OS TCP buffer
        //TODO("come up with something better inside the network manager");
        chl.send(&dummyMessage, sizeof(dummyMessage));

        //std::cout << "Sender " + ToString(initThrdIdx) + " otIdx " + ToString(otIdx) << std::endl;

        auto& cutnChoose = *cutnChooseSets.get();
        block myOTMsgProof = ZeroBlock;


        //std::cout << "Sender " + ToString(initThrdIdx) + " opening" << std::endl;

        // send over all the open circuits
        for (u64 cirIdx : cutnChoose[0])
        {
            if (cirIdx >= startIdx && cirIdx < endIdx)
            {
                //std::cout << "Sender " + ToString(initThrdIdx) + "  opening " + ToString(cirIdx) << std::endl;

                mMyCircuits[cirIdx].open(mCircuit, chl, mRole, myOTMsgProof);
                mMyCircuits[cirIdx].clear();
            }
        }

        // this message blocks until everything before has been sent. 
        //Temp fixed for sending too much stuff and overflowing the OS TCP buffer
        //TODO("come up with something better inside the network manager");
        chl.send(&dummyMessage, sizeof(dummyMessage));

        //std::cout << "Sender " + ToString(initThrdIdx) + "  opened w/ prf "<< myOTMsgProof << std::endl;

        chl.asyncSendCopy(&myOTMsgProof, sizeof(block));

#ifdef ASYNC_PSI
        u64 otsPerPSI = AsyncPsiSender::PsiOTCount(mBucketSize, mPsiSecParam);
#else
        u64 otsPerPSI = PsiSender::PsiOTCount(mBucketSize, mPsiSecParam);
#endif // ASYNC_PSI


        u64 numSkip = (mNumInitThreads - 1) * mBucketSize;
        auto evalIter = cutnChoose[1].begin() + initThrdIdx * mBucketSize;
        for (u64 bcktIdx = initThrdIdx; bcktIdx < mBuckets.size(); bcktIdx += mNumInitThreads)
        {
            while (otDoneIdx < otIdx + otsPerPSI)std::this_thread::sleep_for(std::chrono::milliseconds(1));

            mBuckets[bcktIdx].initSend(mCircuit, chl, mBucketSize, mPsiSecParam, mRole, mMyCircuits,
                evalIter, prng, mTheirKProbe, mMyKProbe, mOTRecv[initThrdIdx], otIdx, mIndexArray);

            if (bcktIdx + mNumInitThreads < mBuckets.size())
                evalIter += numSkip;
        }
        //std::cout << "Sender " + ToString(initThrdIdx) + " kprobe" << std::endl;

        // this message blocks until everything before has been sent. 
        //Temp fixed for sending too much stuff and overflowing the OS TCP buffer
        //TODO("come up with something better inside the network manager");
        chl.send(&dummyMessage, sizeof(dummyMessage));


        for (u64 bcktIdx = initThrdIdx; bcktIdx < mBuckets.size(); bcktIdx += mNumInitThreads)
        {
            mBuckets[bcktIdx].initKProbeInputSend(mCircuit, chl, mTheirKProbe, prng, mRole, mIndexArray);
        }

        chl.close();
    }


    BitVector DualExActor::execute(u64 evalIdx, PRNG& prng, const BitVector & input, Timer& timer)
    {
        //u64 evalIdx = mEvalIdx++;
        u64 bufferOffset = evalIdx % mLabels.size();
        //std::lock_guard<std::mutex>lock(mMtxs[bufferOffset]);

        //std::cout << "recv start " << evalIdx << "  " << bufferOffset << " " << (int)mRole << std::endl;


        if (input.size() != mCircuit.Inputs()[(int)mRole]) throw std::invalid_argument("input size");
        Bucket& bucket = mBuckets[evalIdx];

        // pass our inputs to the thread that sends them.
        bucket.mInputPromise.set_value(&input);


        auto& chl = *mRecvMainChls[bufferOffset];
        //chl.asyncSend(&evalIdx, sizeof(evalIdx));

        // evaluate the circuits that we have received
        bucket.evaluate(mCircuit, mTheirKProbe, mMyKProbe, prng, chl, mRole, input, mLabels[bufferOffset], timer);

#ifndef PARALLEL_PSI
        PSIReceiver& psiRecv = bucket.mPsiRecv;
        for (u64 i = 0; i < mBucketSize; ++i)
        {
            block psiInput = bucket.mPsiInputFuture[i].get();
            psiRecv.CommitSend(psiInput, chl, i);
        }
        for (u64 i = 0; i < mBucketSize; ++i)
            psiRecv.CommitRecv(chl, i);
#endif

        block theirOutLabelSeed;
        chl.recv(&theirOutLabelSeed, sizeof(block));

        AES outGen(theirOutLabelSeed);
        outGen.ecbEncBlocks(mIndexArray.data(), mOutLabels[bufferOffset].size(), mOutLabels[bufferOffset].data());

        bucket.mTheirOutputLabelsProm.set_value(&mOutLabels[bufferOffset]);

#ifndef PARALLEL_PSI

        u64 idx = (u64)-1;
        bucket.mTranslationCheckDoneFuture.get();
        for (u64 i = 0; i < mBucketSize; ++i)
        {
            psiRecv.open(chl, i, mRole);

            for (u64 j = 0; j < mBucketSize; ++j)
            {
                if (bucket.mPSIInputPermutes[j] == i)
                    idx = j;
                //return bucket.mOutputs[i];
            }
        }
        return bucket.mOutputs[idx];

#else

        return *bucket.mOutputFuture.get();
#endif

    }



    void DualExActor::sendLoop(u64 bucketOffset, u64 bucketStep, Channel& chl, PRNG& prng)
    {
        mOnlineFuture.get();
        //auto& chl = *mSendMainChls[bucketOffset];

        for (u64 bucketIdx = bucketOffset; bucketIdx < mNumExe; bucketIdx += bucketStep)
        {

            auto& bucket = mBuckets[bucketIdx];


            // receive their input correction and place it in the bucket
            chl.recv(bucket.mTheirInputCorrection);

            // notify the other threads that their input correction has arrived.
            bucket.mTheirInputCorrectionPromise.set_value();



#ifdef PARALLEL_PSI
            bucket.mPsiSend.mCommitedFuture.get();
            bucket.mPsiRecv.mCommitedFuture.get();
#else
            this is not tested.breaking changes have been made.Tho it should / could work in theory
                PSISender& psiSend = bucket.mPsiSend;
#ifdef ASYNC_PSI
            for (u64 i = 0; i < mBucketSize; ++i)
            {
                block psiInput = bucket.mPsiInputFuture[i].get();
                psiSend.AsyncCommitSend(psiInput, chl, i);
            }

            serial AsyncCommitRecv is broken.There is a std::future.get() that blocks.disable that and fill the openBuffs **only** after all receive commits have arrived...
                for (u64 i = 0; i < mBucketSize; ++i)
                    psiSend.AsyncCommitRecv(chl, i);
#else
            for (u64 i = 0; i < mBucketSize; ++i)
                psiSend.CommitRecv(chl, i);
            for (u64 i = 0; i < mBucketSize; ++i)
            {
                block psiInput = bucket.mPsiInputFuture[i].get();
                psiSend.CommitSend(psiInput, chl, i);
            }

#endif
#endif

            bucket.openTranslation(mCircuit, chl);


#ifndef PARALLEL_PSI
            bucket.mTranslationCheckDoneFuture.get();
            for (u64 i = 0; i < mBucketSize; ++i)
                psiSend.open(chl, i);
#endif
        }
    }


    void DualExActor::sendCircuitInputLoop(u64 circuitOffset, u64 circuitStep, u64  bucketOffset, u64 bucketStep, Channel& chl)
    {

#ifdef PARALLEL_PSI
        assert(circuitStep == mBucketSize && "psi channels are not concurrent safe");
#endif

        u64 psiPermuteIdx(circuitOffset);

        ////u64 bucketIdx = bucketOffset;
        for (u64 bucketIdx = bucketOffset; bucketIdx < mNumExe; bucketIdx += bucketStep)
        {

            auto& bucket = mBuckets[bucketIdx];
            const BitVector& input = *bucket.mInputFuture.get();
            bucket.sendCircuitInputs(mCircuit, input, mRole, chl, circuitOffset, circuitStep);

#ifdef PARALLEL_PSI
            psiPermuteIdx = circuitOffset;

            auto& psiChl = chl;

#ifdef ASYNC_PSI
            block psiInput = bucket.mPsiInputFuture[psiPermuteIdx].get();

            bucket.mPsiSend.AsyncCommitSend(psiInput, psiChl, psiPermuteIdx);

            bucket.mPsiSend.AsyncCommitRecv(psiChl, psiPermuteIdx);
#else
            bucket.mPsiSend.CommitRecv(psiChl, psiPermuteIdx);

            block psiInput = bucket.mPsiInputFuture[psiPermuteIdx].get();

            bucket.mPsiSend.CommitSend(psiInput, psiChl, psiPermuteIdx);
#endif
            //bucket.mPsiSend.mCommitedFuture.get();

            bucket.mTranslationCheckDoneFuture.get();

            bucket.mPsiSend.open(psiChl, psiPermuteIdx);
#endif
        }

    }

    void DualExActor::evalThreadLoop(u64 circuitOffset, u64 circuitStep, u64  bucketOffset, u64 bucketStep, PRNG& prng, Channel& chl)
    {
#ifdef PARALLEL_PSI
        assert(circuitStep == mBucketSize && "psi channels are not concurrent safe");
#endif

        //std::vector<u64> psiIdxs(mBucketSize);
        std::vector<block> wireBuff(mCircuit.OutputCount() * 2);


#ifdef ADAPTIVE_SECURE
        std::vector<block> adaptiveSecureTableMasks(mCircuit.NonXorGateCount() * 2);
#endif 
        mOnlineFuture.get();
        Timer timer;

        u64 psiPermuteIdx = circuitOffset;
        for (u64 bucketIdx = bucketOffset; bucketIdx < mNumExe; bucketIdx += bucketStep)
        {
            auto& bucket = mBuckets[bucketIdx];

            u64 circuitIdx = circuitOffset;
            //for (u64 circuitIdx = circuitOffset, i=0; circuitIdx < mBucketSize; circuitIdx += circuitStep, ++i)
            //{
                //std::cout << i << std::endl; 
            block psiInput = bucket.evalCircuit(
                circuitIdx,
                mCircuit,
                prng,
                mMyKProbe,
                mLabels[bucketOffset][circuitIdx],
                chl,
#ifdef ADAPTIVE_SECURE
                adaptiveSecureTableMasks,
                mIndexArray,
#endif
                mRole,
                timer);


            {
                std::lock_guard<std::mutex> lock(bucket.mPsiInputMtx);

                // atomic increment the head pointer of there the next psi value should be stored
                i32 psiIdx = bucket.mPSIIdxHead++;
                psiPermuteIdx = bucket.mPSIInputPermutes[psiIdx];

                for (u64 i = 0; i < psiIdx; ++i)
                    if (eq(psiInput, bucket.mPSIInputBlocks[bucket.mPSIInputPermutes[i]]))
                    {
                        psiInput = prng.get<block>();
                    }

                // store our psi value.
                bucket.mPSIInputBlocks[psiPermuteIdx] = psiInput;
            }
            bucket.mPsiInputPromise[psiPermuteIdx].set_value(psiInput);
            psiInput = bucket.mPsiInputFuture[circuitIdx].get();


            //std::cout << psiInput << std::endl;

#ifdef PARALLEL_PSI

            //std::lock_guard<std::mutex> lock(psiChannelLocks[circuitIdx]);

            bucket.mPsiRecv.CommitSend(psiInput, chl, circuitIdx);
            //}

            ///for (u64 circuitIdx = circuitOffset, i = 0; circuitIdx < mBucketSize; circuitIdx += circuitStep, ++i)
            //{
            //u64 circuitIdx = bucket.mPSIInputPermutes[psiIdx];

            bucket.mPsiRecv.CommitRecv(chl, circuitIdx);
            timer.setTimePoint("psiCommited");
            //}

            //for (u64 circuitIdx = circuitOffset, i = 0; circuitIdx < mBucketSize; circuitIdx += circuitStep, ++i)
            //{
#endif
            bucket.checkTranslation(mCircuit, circuitIdx, wireBuff, mRole);
            timer.setTimePoint("TranslationOK");

#ifdef PARALLEL_PSI
            //}
            //for (u64 circuitIdx = circuitOffset, i = 0; circuitIdx < mBucketSize; circuitIdx += circuitStep, ++i)
            //{
            //u64 circuitIdx = bucket.mPSIInputPermutes[psiIdx];

            bool match = bucket.mPsiRecv.open(chl, circuitIdx, mRole);

            timer.setTimePoint("PSIOpen");

			if (match)
			{
				bucket.mOutputProm.set_value(&bucket.mOutputs[circuitIdx]);
			}
			else
			{ 
				u32 missCount = ++bucket.mOutputMissCount;
				if (missCount == bucket.mTheirCircuits.size())
				{
					try {
						std::cout << "No items found in the intersection " << std::endl;
						throw std::runtime_error("No items found in the intersection " LOCATION);
					}
					catch (...)
					{
						bucket.mOutputProm.set_exception(std::current_exception());
					}
				}
			}
			//psiRecv.CommitSend()
			//bucket.checkTranslation(mCircuit, circuitIdx, wireBuff, mRole);
		//}
#endif

        }


        if (PRINT_EVAL_TIMES)
        {


#ifdef ASYNC_PSI
            std::string psi("Async_");
#else
            std::string psi("Sync_");
#endif
            std::string filename = "timeFile_" + psi + ToString(mNumExe) + "-" + ToString(mNumOpened) + "_b" + ToString(mBucketSize) + "_" + ToString(bucketOffset) + "_" + ToString(circuitOffset) + ".txt";
            std::fstream file;
            file.open(filename, std::ios::out);

            if (file.is_open() == false)
                std::cout << "couldnt open file " << filename << std::endl;

            file << timer;
        }
    }

    void DualExActor::printTimes(std::string filename)
    {
        //		u64 numParallelEvals = mRecvMainChls.size();
        //		u64 threadsPer = mEvalThreads.size() / numParallelEvals;
        //
        //		std::cout << "open file range " << (filename + "_" + ToString(numParallelEvals) + "_" + ToString(threadsPer)) << std::endl;
        //
        //
        //		for (u64 i = 0; i <numParallelEvals; ++i)
        //		{
        //
        //			for (u64 j = 0; j < threadsPer; ++j)
        //			{
        //
        //				std::fstream file;
        //				file.open(filename + "_" + ToString(i) + "_" + ToString(j), std::ios::out);
        //
        //				if (file.is_open() == false)
        //					std::cout << "couldnt open file " << (filename + "_" + ToString(i) + "_" + ToString(j)) << std::endl;
        //
        //				file << mTimes[i*numParallelEvals + j];
        //			}
        //
        ////		}
        /////*
        //		circuitOffset + bucketOffset * bucketStep
        //		out << mTimes[0] << std::endl;
        //*/
    }

}

