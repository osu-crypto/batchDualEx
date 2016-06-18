#include "BtSocket.h"

namespace libBDX
{


	BtSocket::BtSocket(BtIOService& ios) :
		mHandle(ios.mIoService),
		mSendStrand(ios.mIoService),
		mRecvStrand(ios.mIoService),
		mStopped(false),
		mOutstandingSendData(0),
		mMaxOutstandingSendData(0),
		mTotalSentData(0)
	{

	}

}
