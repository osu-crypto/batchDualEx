#include "Common/Defines.h"
#include "Crypto/Commit.h"
#include "Common/BitVector.h"
//#include "Common/Timer.h"

namespace libBDX {


	const block ZeroBlock = _mm_set_epi64x(0, 0);
	const block OneBlock = _mm_set_epi64x(0, 1);

	std::ostream& operator<<(std::ostream& out, const block& block)
	{
		out << std::hex;
		u64* data = (u64*)&block;

		out << std::setw(16) << std::setfill('0') << data[0]
			<< std::setw(16) << std::setfill('0') << data[1];

		out << std::dec << std::setw(0);

		return out;
	}

	std::ostream* gOut = &std::cout;



	std::ostream& operator<<(std::ostream& out, const Commit& comm)
	{
		out << std::hex;

		u32* data = (u32*)comm.data();

		out << std::setw(8) << std::setfill('0') << data[0]
			<< std::setw(8) << std::setfill('0') << data[1]
			<< std::setw(8) << std::setfill('0') << data[2]
			<< std::setw(8) << std::setfill('0') << data[3]
			<< std::setw(8) << std::setfill('0') << data[4];

		out << std::dec << std::setw(0);

		return out;
	}

	std::ostream& operator<<(std::ostream& out, const BitVector& vec)
	{/*
		 out << std::hex;

		 for (u64 i = 0; i < vec.size_bytes(); ++i)
			  out << std::setw(2) << std::setfill('0') << (int)vec.data()[i];

		 out << std::dec << std::setw(0);*/

		for (u64 i = 0; i < vec.size(); ++i)
		{
			if (vec[i])
				out << "1";
			else
				out << "0";
		}

		return out;
	}

	void split(const std::string &s, char delim, std::vector<std::string> &elems) {
		std::stringstream ss(s);
		std::string item;
		while (std::getline(ss, item, delim)) {
			elems.push_back(item);
		}
	}

	std::vector<std::string> split(const std::string &s, char delim) {
		std::vector<std::string> elems;
		split(s, delim, elems);
		return elems;
	}


	//static Timer gTimer;
	//Timer& timer
	//{
	//	return gTimer;
	//}

	//std::ostream& operator<<(std::ostream& out, const Commit& comm)
	//{
	//	out << std::hex;


	//	for (u64 i = 0; i < comm.size(); ++i)
	//	{
	//		out << std::setw(2) << std::setfill('0') << comm.data[i];
	//	}
	//	out << std::dec << std::setw(0);

	//	return out;
	//}
}
