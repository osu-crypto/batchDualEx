#include "Common.h"
#include <fstream>
#include <cassert>
#include "Common/Logger.h"

using namespace libBDX;

static std::fstream* file = nullptr;
std::string testData("../..");

void InitDebugPrinting(std::string filePath)
{
	Lg::out << "changing sink" << Lg::endl;

	if (file == nullptr)
	{
		file = new std::fstream;
	}
	else
	{
		file->close();
	}

	file->open(filePath, std::ios::trunc | std::ofstream::out);
	if (!file->is_open())
		throw std::runtime_error("");


	//time_t now = time(0);

	Lg::SetSink(*file);

	
	//Lg::out << "Test - " << ctime(&now) << Lg::endl;
}
