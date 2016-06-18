
#include "Common/BitVector.h"
#include "Crypto/PRNG.h"
#include "Common/ByteStream.h"
#include "Common/Logger.h"

#include <fstream>
namespace libBDX {

	using namespace std;



	//u8 BitReference::bit()
	//{
	//	return (*mByte & mMask) >> mShift;
	//}
	void BitReference::operator=(bool val)
	{
		if (val)
		{
			*mByte |= mMask;
		}
		else
		{
			*mByte &= ~mMask;
		}
	}

	BitReference::operator u8() const
	{
		return (*mByte & mMask) >> mShift;
	}


	void BitVector::randomize(PRNG& G)
	{
		G.get_u8s(mData, sizeBytes());
	}

	void BitVector::randomize_at(int a, int nb, PRNG& G)
	{
		if (nb < 1)
			throw invalid_length();
		G.get_u8s(mData + a, nb);
	}

	std::string BitVector::hex()
	{
		std::stringstream s;

		s << std::hex;
		for (unsigned int i = 0; i < sizeBytes(); i++)
		{
			s << std::setw(2) << std::setfill('0') << int(mData[i]);
		}
		
		return s.str();
	}

	void BitVector::output(ostream& s, bool human) const
	{
		if (human)
		{
			s << mNumBits << " " << std::hex;
			for (unsigned int i = 0; i < sizeBytes(); i++)
			{
				s << int(mData[i]) << " ";
			}
			s << dec << endl;
		}
		else
		{
			u64 len = mNumBits;
			s.write((char*)&len, sizeof(int));
			s.write((char*)mData, sizeBytes());
		}
	}


	void BitVector::input(istream& s, bool human)
	{
		if (s.peek() == EOF)
		{
			if ((size_t)s.tellg() == 0)
			{
				cout << "IO problem. Empty file?" << endl;
				throw file_error();
			}
			throw end_of_file();
		}
		int len;
		if (human)
		{
			s >> len >> std::hex;
			reset(len);
			for (size_t i = 0; i < sizeBytes(); i++)
			{
				s >> mData[i];
			}
			s >> dec;
		}
		else
		{
			s.read((char*)&len, sizeof(int));
			reset(len);
			s.read((char*)mData, sizeBytes());
		}
	}


	void BitVector::pack(ByteStream& o) const
	{
		o.append((u8*)mData, sizeBytes());
	}


	void BitVector::unpack(ByteStream& o)
	{
		o.consume((u8*)mData, sizeBytes());
	}



	BitVector::BitVector(BitVector&& rref)
		:
		mData(rref.mData),
		mNumBits(rref.mNumBits),
		mAllocBytes(rref.mAllocBytes)
	{ 
		rref.mData = nullptr;
		rref.mAllocBytes = 0;
		rref.mNumBits = 0;
	}

	BitVector::BitVector(u8 * data, u64 length)
		:
		mData(nullptr),
		mNumBits(0),
		mAllocBytes(0)
	{
		append(data, length, 0);
	}

	block& BitVector::ToBlock() const
	{
		assert(mNumBits == 128 || mNumBits == (8 * 20));
		return *(block*)(mData);
	}


	void BitVector::assign(const block& b)
	{
		reset(128);
		memcpy(mData, ByteArray(b), sizeBytes());
	}

	void BitVector::assign(const BitVector& K)
	{
		reset(K.mNumBits);
		memcpy(mData, K.mData, sizeBytes());
	}
	void BitVector::assign_zero()
	{
		memset(mData, 0, sizeBytes());
	}

	void BitVector::append(u8* data, u64 length, u64 offset)
	{

		auto bitIdx = mNumBits;
		auto destOffset = mNumBits % 8;
		auto destIdx = mNumBits / 8;
		auto srcOffset = offset % 8;
		auto srcIdx = offset / 8;
		auto byteLength = (length + 7) / 8;

		resize(mNumBits + length);
		
		static const u8 masks[8] = {1,2,4,8,16,32,64,128};

		assert(data);

		// if we have to do bit shifting, copy bit by bit
		if (srcOffset || destOffset)
		{

			//TODO("make this more efficient");
			for (u64 i = 0; i < length; ++i, ++bitIdx, ++offset)
			{
				u8 bit = data[offset / 8] & masks[offset % 8];
				(*this)[bitIdx] = bit;
			}
		}
		else
		{
			memcpy(mData + destIdx, data + srcIdx, byteLength);
		}
		

		//u8 srcLowBitsMask = ((u8)-1) << ;

		//mData[destIdx] = 
		//	(mData[destIdx] & ((u8)-1 >> 8 - destOffset)) |
		//	((data[0] >> srcOffset) << destOffset);

		//for (u64 i = 1; i < byteLength; ++i)
		//{
		//	mData[destIdx + i - 1] |= (data[i] << (8 + destOffset - srcOffset));

		//	mData[destIdx + i] = data[i] 
		//}

		//auto end = byteLength - 1;
		//for (u64 i = 0; i < end; ++i)
		//{
		//	mData[i] = mData[i] >> srcOffset | mData[i + 1] << (8 - srcOffset);
		//}

		//mData[end] = mData[end] >> srcOffset;
	}

	void BitVector::reserve(u64 bits)
	{
		u64 curBits = mNumBits;
		resize(bits);

		mNumBits = curBits;
	}

	void BitVector::resize(u64 newSize)
	{
		size_t new_nbytes = DIV_CEIL((int)newSize, 8);
		 
		if (mAllocBytes < new_nbytes)
		{
			u8* tmp = new u8[new_nbytes]();
			mAllocBytes = new_nbytes;

			memcpy(tmp, mData, sizeBytes());

			if (mData)
				delete[] mData;

			mData = tmp;
		} 
		mNumBits = newSize;
	}

	// erases original contents
	void BitVector::reset(size_t new_nbits)
	{
		u64 newSize = (new_nbits+7)/ 8;

		if (newSize > mAllocBytes)
		{
			if (mData)
				delete[] mData;

			mData = new u8[newSize]();
			mAllocBytes = newSize;
		}
		else
		{
			memset(mData, 0, newSize);
		}

		mNumBits = new_nbits;
	}

	void BitVector::copy(const BitVector& src, u64 idx, u64 length)
	{
		resize(0);
		append(src.mData, length, idx);

	}


	BitVector& BitVector::operator=(const BitVector& K)
	{
		if (this != &K) { assign(K); }
		return *this;
	}


	void BitVector::set_byte(u64 i, u8 b)
	{
		assert(i < sizeBytes());
		mData[i] = b;
	}

	void BitVector::set_u64(u64 i, u64 w)
	{
		assert((i + 1) * 64 <= mNumBits);
		u64 offset = i * sizeof(u64);
		memcpy(mData + offset, (u8*)&w, sizeof(u64));
	}

	//int BitVector::get_bit(int i) const
	//{
	//	assert(i < mNumBits);
	//	return (mData[i / 8] >> (i % 8)) & 1;
	//}

	BitReference BitVector::operator[](const u64 idx) const
	{
		assert(idx < mNumBits);
		return BitReference(mData + (idx / 8), (u8)(idx % 8));
	}

	//void BitVector::set_bit(int i, unsigned int a)
	//{
	//	assert(i < mNumBits);
	//	int j = i / 8, k = i & 7;
	//	if (a)
	//	{
	//		mData[j] |= (u8)(1UL << k);
	//	}
	//	else
	//	{
	//		mData[j] &= (u8)~(1UL << k);
	//	}
	//}

	BitVector BitVector::operator^(const BitVector& B)const
	{
		BitVector ret(*this);

		ret ^= B;

		return ret;
	}

	void BitVector::operator&=(const BitVector & A)
	{
		for (u64 i = 0; i < sizeBytes(); i++)
		{
			mData[i] &= A.mData[i];
		}
	}

	void BitVector::operator^=(const BitVector& A)
	{
		assert(mNumBits == A.mNumBits);
		for (u64 i = 0; i < sizeBytes(); i++)
		{
			mData[i] ^= A.mData[i];
		}
	}



	bool BitVector::equals(const BitVector& rhs) const
	{

		assert(mNumBits == rhs.mNumBits);
		u64 lastByte = sizeBytes() - 1;
		for (u64 i = 0; i < lastByte; i++)
		{
			if (mData[i] != rhs.mData[i]) { return false; }
		}

		// numBits = 4 
		// 00001010
		// 11111010
		//     ^^^^ compare these

		u64 rem = mNumBits & 7;
		u8 mask = ((u8)-1) >> (8-rem);
		if ((mData[lastByte] & mask) != (rhs.mData[lastByte] & mask))
			return false;

		return true;
	}

	std::string BitVector::str()
	{
		std::stringstream ss;
		ss << std::hex;
		for (u64 i(0); i < sizeBytes(); ++i)
			ss << (int)mData[i];
		return ss.str();
	}

	u8 BitVector::parity()
	{
		u8 bit = 0;

		u64 lastByte = mNumBits /8;
		for (u64 i = 0; i < lastByte; i++)
		{ 

			bit ^= ( mData[i]       & 1); // bit 0
			bit ^= ((mData[i] >> 1) & 1); // bit 1
			bit ^= ((mData[i] >> 2) & 1); // bit 2
			bit ^= ((mData[i] >> 3) & 1); // bit 3
			bit ^= ((mData[i] >> 4) & 1); // bit 4
			bit ^= ((mData[i] >> 5) & 1); // bit 5
			bit ^= ((mData[i] >> 6) & 1); // bit 6
			bit ^= ((mData[i] >> 7) & 1); // bit 7
		}
		 
		u64 lastBits = mNumBits -  lastByte * 8;
		for (u64 i = 0; i < lastBits; i++)
		{
			bit ^= (mData[lastByte] >> i) & 1;
		}

		return bit;
	}

}