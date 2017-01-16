
#project(libBDXTests)

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})


add_library(libBDXTests STATIC ${SRCS})

target_link_libraries(libBDXTests libBDX)
