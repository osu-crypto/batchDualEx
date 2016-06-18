# Batch Dual Execution
Batch Dual Execution framework for secure multiparty computation. This is the implementation of **_Faster Malicious 2-party Secure Computation with Online/Offline Dual Execution_** \[[ePrint](https://eprint.iacr.org/2016/633), [Usenix'16](https://www.usenix.org/conference/usenixsecurity16/list-accepted-papers)\] by Peter Rindal and Mike Rosulek. The implementation was written by Peter Rindal with some partial code provided by [Marcel Keller](http://www.bristol.ac.uk/engineering/people/marcel-k-keller/index.html) ([OT Extension](http://github.com/bristolcrypto/apricot)) and the [Scapi](https://github.com/cryptobiu/scapi) project. This work was supported by NSF award 1149647 and the first author is also supported by an ARCS foundation fellowship.

#### Abstract

>We ~~describe~~ *implement* a highly optimized protocol for general-purpose secure two-party computation (2PC) in the presence of malicious adversaries. Our starting point is a protocol of Kolesnikov et al. (TCC 2015). We adapt that protocol to the online/offline setting, where two parties repeatedly evaluate the same function (on possibly different inputs each time) and perform as much of the computation as possible in an offline preprocessing phase before their inputs are known. Along the way we develop several significant simplifications and optimizations to the protocol.
>
>We have implemented a prototype of our protocol and report on its performance. When two parties on Amazon servers in the same region use our implementation to securely evaluate the AES circuit 1024 times, the amortized cost per evaluation is *5.1ms offline + 1.3ms online*. The total offline+online cost of our protocol is in fact less than the *online* cost of any reported protocol with malicious security. For comparison, our protocol's closest competitor (Lindell \& Riva, CCS 2015) uses 74ms offline + 7ms online in an identical setup.
>
>Our protocol can be further tuned to trade performance for leakage. As an example, the performance in the above scenario improves to *2.4ms offline + 1.0ms online* if we allow an adversary to learn a single bit about the honest party's input with probability $2^{-20}$ (but not violate any other security property, e.g. correctness).


## Install

This library has been tested and designed to work on both Windows and Linux. 

#### Windows

On Windows the primary way to build the library is the provided Visual Studio Solution. Once the third party dependencies have been made, the solution should build the library, unit tests, and the frontend appliation. The third party dependencies include [Boost](http://www.boost.org/), [Crypto++](https://www.cryptopp.com/), [Miracl-SDK](http://www.miracl.com/miracl-sdk), [Mpir](http://mpir.org/), and [NTL](http://www.shoup.net/ntl/). For all but the NTL library, the repository contains powershell scripts to download and build them. These scripts are located in the ./thirdparty/win/ folder. Although there is a script called getNTL.ps1, it only downloads NTL but does not build it. To build NTL, users can either follow the instructions provided by NTL (using a emulated unix compiler) or use visual studio. 

There are two location which the library by default looks for these dependencies, C:/libs/* and the relatitive directory ./thirdparty/win/. By default, the scripts will place the libraries in the folder in which they are executed. 

For those who are curious, the Miracl-SDK script downloads a clone of the Miracl-SDK hosted on one of the author's github accounts. It contains a few modifications to the libraries configuration and a Visual Studio Solution to build the library. Any *Multi-threaded* build of the Miracl-SDK should work but it is advised to use the provided version.

#### Linux

Building on linux consists of aquiring the dependencies and calling make. The dependencies include [Boost](http://www.boost.org/), [Crypto++](https://www.cryptopp.com/), [Miracl-SDK](http://www.miracl.com/miracl-sdk), [Mpir](http://mpir.org/), and [NTL](http://www.shoup.net/ntl/). The simplest way to obtain them is to call the all.get bash script on ./thirdparty/linux folder.

`cd ./thirdparty/linux`<br>
`bash all.get`

**Note**: the all.get script tries to install bzip2, unzip, gcc-c++, m4 and will prompt for root access. If these are already installed just Ctrl-c through the prompt.

Once built, return to the root directory and call 

`make`

## Usage

#### Unit Tests

The unit tests can be run be executing

`./Release/frontend.exe -u`

When using Visual Studio, the is an additional project which integrates the tests into the Test Explorer. This window can be found under Tests->windows->Test Explorer. From here all the unit tests can be run. Note that if you get the following message

> Test Failed - [Test Name]<br>
>Result Message:	A 64-bit test cannot run in a 32-bit process. Specify platform as X64 to force test run in X64 mode on X64 machine.

then press Alt + s + s + a  -> x64    or Test -> Test Settings -> Default processor Architecture -> x64. Visual studio switches to x86 sometimes and must be set back to x64 since there is no x86 library. 

Also, the *ReadBris tests may fail if they can't find the circuit file. You can ignore this or execute the tests from the appropriate folder.

#### Primary Program

The primary program can be run as a single executable. i.e.

`./Release/frontend.exe`

Or it can be run as two seperate programs where two programs perform each half of the protocol. In this case, call

`./Release/frontend.exe -r 0 &`<br>
`./Resease/frontend.exe -r 1`

Or call them in different terminals without the &. Many other parameters can be set too. This includes:
* Port number (-p, --port = 1212)
* Hostname (-h, --hostname = localhost)
* Number of execution (-n, --nExec = 128)
* Bucket size (-b, --bcktSize = 4)
* Number of opened circuit (-o, --open = 0)
* Circuit file (-f, --file = ./circuits/AES-non-expanded.txt)
* Perform a ping test (-i, --ping = 0)
* Concurrent Setup (-s, --setupConcurrently = 4)
* Concurrent Evlauation (-e, --evalConcurrently = 1)
* Threads per evaluation (-c, --circuitThreads = -b)
* Statistical Security (-k, --statisticalK = 40)

**NOTE**: By default there are no open circuits in the cut and choose, therefore its insecure. For secure parameters, refer to the provided paper.


## Help

Still having issues? Contact Me, Peter Rindal by email at rindalp@oregonstate.edu. If you have build issues, please let me know. I would like it to be easy to build and if its not I'd like to fix that.
