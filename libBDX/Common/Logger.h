#pragma once
#include <string>
#include <vector>
#include "Common/Defines.h"
#include <list>
#include <atomic>
#include <boost/thread/tss.hpp>
#include <mutex>

#ifdef _MSC_VER
# include <windows.h> 
#endif

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif
#ifdef GetMessage
#undef GetMessage
#endif

namespace libBDX
{

	//#define LOGGER_DEBUG(x) Lg::out x

	class LggerStream;

	//void Cleanup_Miracl(Miracl* miracl)
	//{
	//	if (miracl)
	//		delete miracl;
	//}

	//static boost::thread_specific_ptr<std::stringstream> line;
	//static std::stringstream& getLine()
	//{
	//	if (!line.get())
	//	{
	//		line.reset(new std::stringstream());
	//	}
	//	return *line.get();
	//}

	//class LggerThreadInfo
	//{
	//	u64 mThreadID;
	//	std::string mName;
	//	std::list<std::pair<u32, std::stringstream>>* mBuffer;
	//};

	class Lg
	{
	public:
#ifdef _MSC_VER
		static const HANDLE __m_hConsole;
#endif

		enum class Color {
			LightGreen = 2,
			LightGrey = 3,
			LightRed = 4,
			OffWhite1 = 5,
			OffWhite2 = 6,
			Grey = 8,
			Green = 10,
			Blue = 11,
			Red = 12,
			Pink = 13,
			Yellow = 14,
			White = 15
		};
		
		const static Color ColorDefault;

		enum Tag {
			all = 4294967295,
			None = 0,
			Debug = 1 << 0,
			BaseOT = 1 << 1,
			ExtRecvOT = 1 << 2,
			ExtSendOT = 1 << 3,
			NetMgr = 1 << 4,
			Circuit = 1 << 5,
			_unused06 = 1 << 6,
			_unused07 = 1 << 7,
			_unused08 = 1 << 8,
			_unused09 = 1 << 9,
			_unused10 = 1 << 10,
			_unused11 = 1 << 11,
			_unused12 = 1 << 12,
			_unused13 = 1 << 13,
			_unused14 = 1 << 14,
			_unused15 = 1 << 15,
			_unused16 = 1 << 16,
			_unused17 = 1 << 17,
			_unused18 = 1 << 18,
			_unused19 = 1 << 19,
			_unused20 = 1 << 20,
			_unused21 = 1 << 21,
			_unused22 = 1 << 22,
			_unused23 = 1 << 23,
			_unused24 = 1 << 24,
			_unused25 = 1 << 25,
			_unused26 = 1 << 26,
			_unused27 = 1 << 27,
			_unused28 = 1 << 28,
			_unused29 = 1 << 29,
			_unused30 = 1 << 30,
			_unused31 = 1 << 31
		};

		enum Modifier
		{
			endl
		};

		static LggerStream out;

		static void SetSink(std::ostream& out);

		//static LggerStream& stream()
		//{
		//	return out;
		//}
		
		//static std::unique_lock<std::mutex>&& getPrintLock()
		//{
		//	return std::move(std::unique_lock<std::mutex>(mMtx));
		//}

		static void EnableTag(const Tag& tag);
		static void DisableTag(const Tag& tag);
		static void setThreadName(const std::string name);
		static void setThreadName(const char* name);

		static std::mutex mMtx;

	private:

	};




	class LggerStream
	{
	public:
		friend class Lg;
		std::ostream* mSink;
		Lg::Tag mEnabledTags, mCurTags;
		//std::list<std::pair<u32, std::stringstream>> mBuffer;


		LggerStream(std::ostream& stream)
			:mSink(&stream),
			mEnabledTags(Lg::None),
			mCurTags(Lg::None)
		{
		}
		~LggerStream()
		{
			if (mSink)
				mSink->flush();
			//std::stringstream t;
			//mBuffer.emplace_back(Lg::None, std::move(t));
		}

		template<typename T>
		LggerStream& operator<<(const T& in)
		{
			//if ((u32)mCurTags & (u32)mEnabledTags || mCurTags == Lg::Tag::None || mCurTags == Lg::Tag::all)
			//{

				//getLine() << in;
				//if (mSink)
				//{

			*mSink << in;
			//}
			//else
			//{
			//	mBuffer.back().second << in;
			//}
		//}

			return *this;
		}
		//static std::mutex mtx;
		LggerStream& operator<<(const Lg::Modifier in)
		{
			//if ((u32)mCurTags & (u32)mEnabledTags || mCurTags == Lg::Tag::None)
			//{


			if (in == Lg::Modifier::endl)
			{
				if (mSink)
				{
					//getLine() << "\n";
					{
						//std::lock_guard<std::mutex> lock(mtx);
						//*mSink << getLine().str();
						*mSink << "\n";
						mSink->flush();
					}
					//getLine() = std::stringstream();
				}
				else
				{
					throw std::runtime_error("not impl");
					//mBuffer.back().second << getLine().str() << "\n";
					//getLine().clear();
					//std::stringstream t;
					//mBuffer.emplace_back(Lg::None, std::move(t));
				}

				mCurTags = Lg::None;
			}
			//}
			return *this;
		}

		//template<>
		LggerStream& operator<<(const Lg::Tag tag)
		{

			//(*(u32*)(&mCurTags)) |= (u32)tag;
			return *this;
		}



		//LggerStream& operator<<(const WORD tag)
		//{

		//	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		//	SetConsoleTextAttribute(hStdout, (WORD)tag);
		//	//system(ColorStrs[(u8)tag]);
		//	return *this;
		//}

		LggerStream& operator<<(const Lg::Color tag);
	};



}
