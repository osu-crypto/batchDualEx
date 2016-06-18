#pragma once

/* This class creates a stream of data and adds stuff onto it.
 * This is used to pack and unpack stuff which is sent over the
 * network
 *
 * Unlike SPDZ-1.0 this class ONLY deals with native types
 * For our types we assume pack/unpack operations defined within
 * that class. This is to make sure this class is relatively independent
 * of the rest of the application; and so can be re-used.
 */
#include "Defines.h"
#include "Network/Channel.h"
#include "Common/BitVector.h"
#include "Common/ArrayView.h"
#include <string.h>
#include <vector>
#include <stdio.h>
#include <iostream> 

namespace libBDX {
	class Commit;
	class Channel;

	class ByteStream : public ChannelBuffer
	{
		u64 mWriteHead, mxlen, mReadHead;  // mWriteHead is the "write head", mReadHead is the "read head"
		u8 *mData;

	protected:
		u8* ChannelBufferData() const override { return mData + mReadHead; }
		u64 ChannelBufferSize() const override { return mWriteHead - mReadHead; };
		void ChannelBufferResize(u64 length) override
		{
			if (length > mxlen)
			{
				delete[] mData;
				mData = new u8[mxlen = length * 2];
			}
			mWriteHead = length;
			mReadHead = 0;
		}


	public:




		void reserve(u64 l);

		void assign(const ByteStream& os);
		ByteStream(const u8* data, u64 length);

		ByteStream(u64 maxlen = 512);
		ByteStream(const ByteStream& os);
		ByteStream& operator=(const ByteStream& os)
		{
			if (this != &os) { assign(os); }
			return *this;
		}
		~ByteStream() { delete[] mData; }

		//u64 get_ptr() const { return mReadHead; }
		u64 size() const { return mWriteHead; }
		u8* data() const { return mData; }
		u8* end() const { return mData + mWriteHead; }

		ByteStream hash()   const;
		// output must have length at least HASH_SIZE
		void hash(ByteStream& output)   const;
		// The following produces a check sum for debugging purposes
		//bigint check_sum()       const;

		void concat(const ByteStream& os);

		void resize(u64 size);

		//void setg(0) { mReadHead = 0; }
		/* If we reset write head then we should reset the read head as well */
		//void setp(0) { mWriteHead = 0; mReadHead = 0; }

		u64 tellp()
		{
			return mWriteHead;
		}

		u64 tellg()
		{
			return mReadHead;
		}
		void setg(u64 loc) {
			if (loc > mWriteHead) throw std::runtime_error("");
			mReadHead = loc;
		}

		void setp(u64 loc)
		{
			if (loc > mxlen) throw std::runtime_error("");
			mWriteHead = loc;
			mReadHead = std::min(mReadHead, mWriteHead);
		}
		// Move len back num
		//void rewind_write_head(int num) { mWriteHead -= num; }

		bool equals(const ByteStream& a) const;
		
		void append(const BitVector& vec)
		{
			append(vec.data(), vec.sizeBytes());
		}

		void append(const block& b)
		{
			append(ByteArray(b), sizeof(block));
		}


		void append(const Commit& comm);

		// Append with no padding for decoding
		void append(const u8* x, const u64 l);
		// Read l u8s, with no padding for decoding
		void consume(u8* x, const u64 l);

		/* Now store and restore different types of data (with padding for decoding) */

		void store_bytes(u8* x, const u32 l); //not really "bytes"...
		void get_bytes(u8* ans, u32& l);      //Assumes enough space in ans

		//void store(unsigned int a);
		//void store(int a) { store((unsigned int)a); }
		//void get(unsigned int& a);
		//void get(int& a) { get((unsigned int&)a); }

		//void store(const bigint& x);
		//void get(bigint& ans);

		//void store(const std::vector<modp>& v, const Zp_Data& ZpD);
		//void get(std::vector<modp>& v, const Zp_Data& ZpD);
		void consume(Commit& comm);
		void consume(block& b)
		{
			consume(ByteArray(b), sizeof(block));
		}

		void operator>>(block& b)
		{
			consume(b);
		}

		void consume(ByteStream& s, u64 l)
		{
			s.reserve(l);
			consume(s.data(), l);
			s.mWriteHead = l;
		}

		u64 capacity() const
		{
			return mxlen;
		}

		template<class T>
		ArrayView<T> getArrayView() const;

		//void Send(Channel& channel) const;
		//void Receive(Channel& socket_num);

		bool operator==(const ByteStream& rhs)
		{
			return equals(rhs);
		}

		bool operator!=(const ByteStream& rhs)
		{
			return !equals(rhs);
		}

		friend std::ostream& operator<<(std::ostream& s, const ByteStream& o);
		friend class PRNG;
	};


	template<class T>
	inline ArrayView<T> ByteStream::getArrayView() const
	{
		return ArrayView<T>((T*)mData, (T*)mData + (mWriteHead / sizeof(T)), false);
	}



}
