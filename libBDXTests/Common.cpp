#include "Common.h"
#include <fstream>
#include <cassert>
#include "cryptoTools/Common/Log.h"

using namespace osuCrypto;

static std::fstream* file = nullptr;
std::string testData(SOLUTION_DIR);

void InitDebugPrinting(std::string filePath)
{
    std::cout << "changing sink" << std::endl;

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
        throw UnitTestFail();

    //time_t now = time(0);

    std::cout.rdbuf(file->rdbuf());
    std::cerr.rdbuf(file->rdbuf());
    //Log::SetSink(*file); 
	
	//std::cout << "Test - " << ctime(&now) << std::endl;
}
