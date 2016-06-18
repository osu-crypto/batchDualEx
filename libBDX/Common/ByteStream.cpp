
#include <fcntl.h>
#include <string.h>

#include "Common/ByteStream.h"
#include "Crypto/sha1.h"
#include "Common/Defines.h"
#include "Common/Exceptions.h"
#include "OT/Math/modp.h"
#include "Crypto/Commit.h"
#include "cryptopp/osrng.h"

namespace libBDX {

	void ByteStream::reserve(u64 l)
	{
		if (l < mxlen) { return; }

		l = 2 * l;      // Overcompensate in the resize to avoid calling this a lot
		u8* nd = new u8[l];
		memcpy(nd, mData, mWriteHead*sizeof(u8));
		delete[] mData;
		mData = nd;
		mxlen = l;
	}


	void ByteStream::assign(const ByteStream& os)
	{
		if (os.mWriteHead >= mxlen)
		{
			delete[] mData;
			mxlen = os.mxlen;
			mData = new u8[mxlen];
		}
		mWriteHead = os.mWriteHead;
		memcpy(mData, os.mData, mWriteHead*sizeof(u8));
		mReadHead = os.mReadHead;
	}


	ByteStream::ByteStream(u64 maxlen)
	{
		mxlen = maxlen; mWriteHead = 0; mReadHead = 0;

		mData = mxlen ? new u8[mxlen] : nullptr;
	}

	ByteStream::ByteStream(const u8 * data, u64 length)
		:mWriteHead(0),
		mxlen(0),
		mReadHead(0),
		mData(nullptr)
	{
		append(data, length);
	}


	ByteStream::ByteStream(const ByteStream& os)
	{
		mxlen = os.mxlen;
		mWriteHead = os.mWriteHead;
		mData = new u8[mxlen];
		memcpy(mData, os.mData, mWriteHead*sizeof(u8));
		mReadHead = os.mReadHead;
	}


	void ByteStream::hash(ByteStream& output) const
	{
		SHA1 ctx;
		output.reserve(SHA1::HashSize);

		ctx.Update(mData, mWriteHead);
		ctx.Final(output.mData);

		output.mWriteHead = SHA1::HashSize;
	}


	ByteStream ByteStream::hash() const
	{
		ByteStream h(SHA1::HashSize);
		hash(h);
		return h;
	}


	//bigint ByteStream::check_sum() const
	//{

	//	unsigned char hash[SHA1::HashSize];

	//	SHA1 ctx; 
	//	ctx.Update(mData, mWriteHead);
	//	ctx.Final(hash);

	//	bigint ans;
	//	bigintFromBytes(ans, hash, SHA1::HashSize);
	//	return ans;
	//}

	void ByteStream::append(const Commit& comm)
	{
		append(comm.data(), comm.size());
	}
	void ByteStream::consume(Commit& comm)
	{
		consume(comm.data(), Commit::size());
	}
	bool ByteStream::equals(const ByteStream& a) const
	{
		if (mWriteHead != a.mWriteHead) { return false; }
		for (u64 i = 0; i < mWriteHead; i++)
		{
			if (mData[i] != a.mData[i]) { return false; }
		}
		return true;
	}


	//void ByteStream::append_random(int num)
	//{
	//	reserve(mWriteHead + num);
	//	//int randomData = open("/dev/urandom", O_RDONLY);
	//	//read(randomData, mData+len, num*sizeof(unsigned char));
	//	//close(randomData);

	//	CryptoPP::OS_GenerateRandomBlock(false, mData + mWriteHead, num*sizeof(unsigned char));
	//	mWriteHead += num;
	//}


	void ByteStream::concat(const ByteStream& os)
	{
		reserve(mWriteHead + os.mWriteHead);
		memcpy(mData + mWriteHead, os.mData, os.mWriteHead*sizeof(u8));
		mWriteHead += os.mWriteHead;
	}

	void ByteStream::resize(u64 size)
	{
		reserve(size);
		setp(size);
	}


	void ByteStream::append(const u8* x, const u64 l)
	{
		reserve(mWriteHead + l);
		memcpy(mData + mWriteHead, x, l*sizeof(u8));
		mWriteHead += l;
	}


	void ByteStream::consume(u8* x, const u64 l)
	{
		if (mReadHead + l > mWriteHead) throw std::runtime_error("");
		memcpy(x, mData + mReadHead, l*sizeof(u8));
		mReadHead += l;
	}


	void encode_u32(u8 *buff, u32 mData)
	{
		//if (mData<0) { throw invalid_length(); }
		buff[0] = mData & 255;
		buff[1] = (mData >> 8) & 255;
		buff[2] = (mData >> 16) & 255;
		buff[3] = (mData >> 24) & 255;
	}

	u32  decode_u32(u8 *buff)
	{
		return buff[0] + 256 * buff[1] + 65536 * buff[2] + 16777216 * buff[3];
		//if (len<0) { throw invalid_length(); }
		//return len;
	}



	void ByteStream::store_bytes(u8* x, const u32 l)
	{
		reserve(mWriteHead + 4 + l);
		encode_u32(mData + mWriteHead, l);
		mWriteHead += 4;

		memcpy(mData + mWriteHead, x, l*sizeof(u8));
		mWriteHead += l;
	}

	void ByteStream::get_bytes(u8* ans, u32& length)
	{
		length = decode_u32(mData + mReadHead); mReadHead += 4;
		memcpy(ans, mData + mReadHead, length*sizeof(u8));
		mReadHead += length;
	}

	//void ByteStream::store(unsigned int l)
	//{
	//	resize(mWriteHead + 4);
	//	encode_length(mData + mWriteHead, l);
	//	mWriteHead += 4;
	//}


	//void ByteStream::get(unsigned int& l)
	//{
	//	l = decode_length(mData + mReadHead);
	//	mReadHead += 4;
	//}


	//void ByteStream::store(const bigint& x)
	//{
	//	int num = numBytes(x);
	//	resize(mWriteHead + num + 5);

	//	(mData + mWriteHead)[0] = 0;
	//	if (x < 0) { (mData + mWriteHead)[0] = 1; }
	//	mWriteHead++;

	//	encode_length(mData + mWriteHead, num); mWriteHead += 4;
	//	bytesFromBigint(mData + mWriteHead, x, num);
	//	mWriteHead += num;
	//}


	//void ByteStream::get(bigint& ans)
	//{
	//	int sign = (mData + mReadHead)[0];
	//	if (sign != 0 && sign != 1) { throw bad_value(); }
	//	mReadHead++;

	//	long length = decode_length(mData + mReadHead); mReadHead += 4;

	//	ans = 0;
	//	if (length != 0)
	//	{
	//		bigintFromBytes(ans, mData + mReadHead, length);
	//		mReadHead += length;
	//		if (sign == 1) { ans = -ans; }
	//	}
	//}



	//void ByteStream::store(const vector<modp>& v, const Zp_Data& ZpD)
	//{
	//	resize(mWriteHead + 4 + 5);
	//	encode_length(mData + mWriteHead, v.size()); mWriteHead += 4;
	//	for (unsigned int i = 0; i < v.size(); i++)
	//	{
	//		v[i].pack(*this, ZpD);
	//	}
	//}


	//void ByteStream::get(vector<modp>& v, const Zp_Data& ZpD)
	//{
	//	long length = decode_length(mData + mReadHead); mReadHead += 4;
	//	v.resize(length);
	//	for (unsigned int i = 0; i < length; i++)
	//	{
	//		v[i].unpack(*this, ZpD);
	//	}
	//}




	//void ByteStream::Send(Channel& channel) const
	//{
	//	//u8 blen[4];
	//	//encode_length(blen,len);
	//	//send(socket_num,blen,4);
	//	//send(socket_num,mData,len);
	//	channel.SendMessage(mData, mWriteHead);

	//}

	//void ByteStream::Receive(Channel& channel)
	//{
	//	//u8 blen[4];
	//	//receive(socket_num,blen,4);

	//	//int nlen=decode_length(blen);
	//	//len=0;
	//	//resize(nlen);
	//	//len=nlen;

	//	//receive(socket_num,mData,len);
	//	std::vector<char> temp;
	//	channel.RecvMessage(temp);
	//	resize(temp.size());
	//	std::copy(temp.begin(), temp.end(), mData);
	//	mWriteHead = temp.size();
	//}

	std::ostream& operator<<(std::ostream& s, const ByteStream& o)
	{
		for (u64 i = 0; i < o.mWriteHead; i++)
		{
			u32 t0 = o.mData[i] & 15;
			u32 t1 = o.mData[i] >> 4;
			s << std::hex << t1 << t0 << std::dec;
		}
		return s;
	}




}