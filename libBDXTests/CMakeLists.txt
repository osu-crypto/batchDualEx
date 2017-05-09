
#project(libBDXTests)

file(GLOB_RECURSE SRCS *.cpp)

add_library(libBDXTests STATIC ${SRCS})
target_include_directories(libBDXTests PUBLIC ${CMAKE_SOURCE_DIR})

target_link_libraries(libBDXTests libBDX)
