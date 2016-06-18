#pragma once

#include <cinttypes>
#include <iomanip>
#include <vector>
#include <sstream>
#include <iostream>
#include "boost/lexical_cast.hpp"
#include <emmintrin.h>
#include <smmintrin.h>



#ifdef _MSC_VER 
#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#define TODO(x) __pragma(message (__FILE__ ":"__STR1__(__LINE__) " Warning:TODO - " #x))
#define ALIGNED(__Declaration, __alignment) __declspec(align(__alignment)) __Declaration 
#else
//#if defined(__llvm__)
#define TODO(x) 
//#else
//#define TODO(x) DO_PRAGMA( message ("Warning:TODO - " #x))
//#endif

#define ALIGNED(__Declaration, __alignment) __Declaration __attribute__((aligned (16)))
#endif

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define LOCATION __FILE__ ":" STRINGIZE(__LINE__)


namespace libBDX {


	typedef uint64_t u64;
	typedef int64_t i64;
	typedef uint32_t u32;
	typedef int32_t i32;
	typedef uint16_t u16;
	typedef int16_t i16;
	typedef uint8_t u8;
	typedef int8_t i8;

	enum Role
	{
		First = 0,
		Second = 1
	};


	template<typename T>
	static std::string ToString(const T& t)
	{
		return boost::lexical_cast<std::string>(t);
	}

	typedef  __m128i block;


#ifdef _MSC_VER
	inline block operator^(const block& lhs, const block& rhs)
	{
		return _mm_xor_si128(lhs, rhs);
	}

	inline block operator&(const block& lhs, const block& rhs)
	{
		return _mm_and_si128(lhs, rhs);
	}

	inline block operator<<(const block& lhs, const u8& rhs)
	{
		return _mm_slli_epi64(lhs, rhs);
	}

	inline block operator+(const block& lhs, const block& rhs)
	{
		return _mm_add_epi64(lhs, rhs);
	}
#endif
	extern const block ZeroBlock;
	extern const block OneBlock;

	inline u8* ByteArray(const block& b)
	{
		return ((u8 *)(&b));
	}


	std::ostream& operator<<(std::ostream& out, const block& block);

	class Commit;
	class BitVector;

	std::ostream& operator<<(std::ostream& out, const Commit& comm);
	std::ostream& operator<<(std::ostream& out, const BitVector& vec);
	//typedef block block;


	void split(const std::string &s, char delim, std::vector<std::string> &elems);
	std::vector<std::string> split(const std::string &s, char delim);


	//class Timer;

	//Timer& getTimer();
}

inline bool eq(const libBDX::block& lhs, const libBDX::block& rhs)
{
	libBDX::block neq = _mm_xor_si128(lhs, rhs);
	return _mm_test_all_zeros(neq, neq) != 0;
}

inline bool notEqual(const libBDX::block& lhs, const libBDX::block& rhs)
{
	libBDX::block neq = _mm_xor_si128(lhs, rhs);
	return _mm_test_all_zeros(neq, neq) == 0;
}

inline bool neq(const libBDX::block& lhs, const libBDX::block& rhs)
{
	libBDX::block neq = _mm_xor_si128(lhs, rhs);
	return _mm_test_all_zeros(neq, neq) == 0;
}

#ifdef _MSC_VER
inline bool operator==(const libBDX::block& lhs, const libBDX::block& rhs)
{
	return eq(lhs, rhs);
}

inline bool operator!=(const libBDX::block& lhs, const libBDX::block& rhs)
{
	return notEqual(lhs, rhs);
}



#endif
