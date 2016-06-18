#pragma once 
#include <list>
#include <chrono>
#include <string>

namespace libBDX 
{ 


	class Timer
	{
		typedef std::chrono::system_clock::time_point timeUnit;

		const static timeUnit mStart;
		std::list< std::pair<timeUnit, std::string>> mTimes;

	public: 
		//Timer() {}
		//Timer(const Timer&);

		const timeUnit& setTimePoint(const std::string& msg);


		friend std::ostream& operator<<(std::ostream& out, const Timer& timer);

	};
	 
}