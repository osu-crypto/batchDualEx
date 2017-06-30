# Batch Dual Execution
Batch Dual Execution framework for secure multiparty computation. This is the implementation of **_Faster Malicious 2-party Secure Computation with Online/Offline Dual Execution_** \[[ePrint](https://eprint.iacr.org/2016/632), [Usenix'16](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/rindal)\] by Peter Rindal and Mike Rosulek. The implementation was written by Peter Rindal with some partial code provided by [Marcel Keller](http://www.bristol.ac.uk/engineering/people/marcel-k-keller/index.html) ([OT Extension](http://github.com/bristolcrypto/apricot)) and the [Scapi](https://github.com/cryptobiu/scapi) project. This work was supported by NSF award 1149647 and the first author is also supported by an ARCS foundation fellowship.

#### Abstract

>We ~~describe~~ *implement* a highly optimized protocol for general-purpose secure two-party computation (2PC) in the presence of malicious adversaries. Our starting point is a protocol of Kolesnikov et al. (TCC 2015). We adapt that protocol to the online/offline setting, where two parties repeatedly evaluate the same function (on possibly different inputs each time) and perform as much of the computation as possible in an offline preprocessing phase before their inputs are known. Along the way we develop several significant simplifications and optimizations to the protocol.
>
>We have implemented a prototype of our protocol and report on its performance. When two parties on Amazon servers in the same region use our implementation to securely evaluate the AES circuit 1024 times, the amortized cost per evaluation is *5.1ms offline + 1.3ms online*. The total offline+online cost of our protocol is in fact less than the *online* cost of any reported protocol with malicious security. For comparison, our protocol's closest competitor (Lindell \& Riva, CCS 2015) uses 74ms offline + 7ms online in an identical setup.
>
>Our protocol can be further tuned to trade performance for leakage. As an example, the performance in the above scenario improves to *2.4ms offline + 1.0ms online* if we allow an adversary to learn a single bit about the honest party's input with probability $2^{-20}$ (but not violate any other security property, e.g. correctness).


## Install

This library has been tested and designed to work on both Windows and Linux. 

#### Windows

On Windows the primary way to build the library is the provided Visual Studio Solution. Once the third party dependencies have been made, the solution should build the library, unit tests, and the frontend appliation. The third party dependencies include [libOTe](https://github.com/osu-crypto/libOTe) and [NTL](http://www.shoup.net/ntl/). Please first clone/build libOTe next to where this repo is cloned to. Then use the getNTL.ps1 script located in the ./thirdparty/win/ folder to obtain NTL. 

There are two location which the library by default looks for these dependencies, C:/libs/* and the relatitive directory ./thirdparty/win/. In addition, libOTe can be located ../libOTe

#### Linux

Building on linux consists of aquiring the dependencies and calling `cmake -G "Unix Makefiles"; make;`. The dependencies include [libOTe](https://github.com/osu-crypto/libOTe) and [NTL](http://www.shoup.net/ntl/). The following commands should build the library and all dependencies 

```
git clone  --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe
git reset --hard  e0727fe6dcfdd4
git submodule update --recursive
cd cryptoTools/thirdparty/linux
bash all.get
cd ../../..
cmake  -G "Unix Makefiles"
make
cd ..
git clone https://github.com/osu-crypto/batchDualEx.git
cd ./batchDualEx/thirdparty/linux
bash ./ntl.get
cd ../..
cmake -G "Unix Makefiles"
make
```




## Usage

#### Unit Tests

The unit tests can be run be executing

`./bin/frontend.exe -u`

When using Visual Studio, the is an additional project which integrates the tests into the Test Explorer. This window can be found under Tests->windows->Test Explorer. From here all the unit tests can be run. Note that if you get the following message

> Test Failed - [Test Name]<br>
>Result Message:	A 64-bit test cannot run in a 32-bit process. Specify platform as X64 to force test run in X64 mode on X64 machine.

then press Alt + s + s + a  -> x64    or Test -> Test Settings -> Default processor Architecture -> x64. Visual studio switches to x86 sometimes and must be set back to x64 since there is no x86 library. 

Also, the *ReadBris tests may fail if they can't find the circuit file. You can ignore this or execute the tests from the appropriate folder.

#### Primary Program

The primary program can be run as a single executable. i.e.

`./bin/frontend.exe`

Or it can be run as two seperate programs where two programs perform each half of the protocol. In this case, call

`./bin/frontend.exe -r 0 &`<br>
`./bin/frontend.exe -r 1`

Or call them in different terminals without the &. Many other parameters can be set too. This includes:
* **Port number (-p, --port = 1212):** The port that -r 1  listens on.
* **Hostname (-h, --hostname = localhost):** The IP address that -r 1 listens on.
* **Number of execution (-n, --nExec = 128):** The number of executions.
* **Bucket size (-b, --bcktSize = 4):** The Bucket size that determines the number of GCs that are evaluated at runtime (See paper for safe parameters). 
* **Number of opened circuit (-o, --open = 0):** The number of GCs that are checked during the cut and choose (See paper for safe parameters).
* **Circuit file (-f, --file = ./circuits/AES-non-expanded.txt):** The location of the circuit file to be computed. Must be in [this format](https://www.cs.bris.ac.uk/Research/CryptographySecurity/MPC/).
* **Perform a ping test (-i, --ping = 0):** Optional argument to have the program compute the throughtput and latency.
* **Concurrent Setup (-s, --setupConcurrently = 4):** The number of threads that should be used during the setup phase.
* **Concurrent Evlauation (-e, --evalConcurrently = 1):** The number of executions that should be performed in parallel. 1 means sequentual. Used to compute throughput.
* **Threads per evaluation (-c, --circuitThreads = -b):** An parameter that allow you to set how many threads are used in the online phase (per evaluation).
* **Statistical Security (-k, --statisticalK = 40)**
* **Verbose (-v, --verbose = false):** print additional information such as detailed timing and communication overhead.

**NOTE**: By default there are no open circuits in the cut and choose, therefore its insecure. For secure parameters, refer to the provided paper.


## Help

Still having issues? Contact Me, Peter Rindal by email at rindalp@oregonstate.edu. If you have build issues, please let me know. I would like it to be easy to build and if its not I'd like to fix that.
