#pragma once

/* Vector of bits */

#include <iostream>
#include <vector> 
#include <stdlib.h>

#include "Common/Defines.h"
#include "Common/Exceptions.h"
//#include "Networking/data.h"
// just for util functions
#include "OT/Math/bigint.h"
//#include "Common/BitIterator.h"
#include "Common/ArrayView.h"
#include "Network/Channel.h"

namespace libBDX
{
	class PRNG;
	class ByteStream;

	class BitReference
	{
		BitReference() = delete;

		u8* mByte;
		u8 mMask, mShift;
	public:

		BitReference(const BitReference& rhs)
			:mByte(rhs.mByte), mMask(rhs.mMask), mShift(rhs.mShift)
		{}

		BitReference(u8* byte, u8 shift)
			:mByte(byte), mMask(1 << shift), mShift(shift) {}

		void operator=(const BitReference& rhs)
		{
			*this = (u8)rhs;
		}

		void operator=(bool val);
		operator u8() const;
		//u8 bit();
	};


	class BitVector : public ChannelBuffer
	{

		u8* mData;
		u64 mNumBits, mAllocBytes;

	public:

		BitVector()
			:mData(nullptr),
			mNumBits(0),
			mAllocBytes(0)
		{}

		BitVector(size_t n)
			:mData(nullptr),
			mNumBits(0),
			mAllocBytes(0)
		{ reset(n); }

		BitVector(const BitVector& K)
			:mData(nullptr),
			mNumBits(0),
			mAllocBytes(0)
		{ assign(K); }

		BitVector(BitVector&& rref);

		~BitVector() {
			delete[] mData;
		}

		BitVector(u8* data, u64 length);


		block& ToBlock()const;
		
		void assign(const block& b);
		void assign(const BitVector& K);
		void assign_zero();

		void append(u8* data, u64 length, u64 offset = 0);
		void append(const BitVector& k) {append(k.data(), k.size());}

		// erases original contents
		void reset(size_t new_nbits = 0);
		void resize(u64 newSize);
		void reserve(u64 bits);

		void copy(const BitVector& src, u64 idx, u64 length);

		u64 size() const { return mNumBits; }
		u64 sizeBytes() const { return (mNumBits + 7)/8; }
		u8* data() const { return mData; }

		BitVector& operator=(const BitVector& K);
		BitReference operator[](const u64 idx) const;
		BitVector operator^(const BitVector& B)const;
		void operator^=(const BitVector& A);
		void operator&=(const BitVector& A);
		bool operator==(const BitVector& k){ return equals(k); }
		bool operator!=(const BitVector& k)const{ return !equals(k); }

		//void set_bit(int i, u32 a);
		void set_byte(u64 i, u8 b);
		void set_u64(u64 i, u64 w);
		
		//int  get_bit(int i) const;
		u8 get_byte(int i) const { return mData[i]; }
		u64 get_u64(int i) const { return *(u64*)(mData + i * 8); }
		bool equals(const BitVector& K) const;
		void randomize(PRNG& G);
		// randomize bytes a, ..., a+nb-1
		void randomize_at(int a, int nb, PRNG& G);

		void output(std::ostream& s, bool human) const;
		void input(std::istream& s, bool human);

		std::string hex();

		u8 parity();
		// Pack and unpack in native format
		//   i.e. Don't care about conversion to human readable form
		void pack(ByteStream& o) const;
		void unpack(ByteStream& o);

		std::string str();




		template<class T>
		ArrayView<T> getArrayView() const;

	protected:
		u8* ChannelBufferData() const override { return mData; }
		u64 ChannelBufferSize() const override { return sizeBytes(); };
		void ChannelBufferResize(u64 len) override
		{
			if (sizeBytes() != len)
				throw std::invalid_argument("asdsdasfaf ;) ");
			//reset(len * 8);
		}


	};
	template<class T>
	inline ArrayView<T> BitVector::getArrayView() const
	{
		return ArrayView<T>((T*)mData, (T*)mData + (sizeBytes() / sizeof(T)), false);
	}

}
