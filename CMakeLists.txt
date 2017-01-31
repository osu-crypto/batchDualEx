cmake_minimum_required (VERSION 3.6)

project(libBDX)

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)

############################################
#           Flag and #defines              #
############################################
add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")
set(CMAKE_C_FLAGS "-ffunction-sections -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread")
set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14")

# Set a default build type for single-configuration
# CMake generators if no build type is set.
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Release)
endif()

if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
  message(WARNING "\nConfiguration NOT set to Release. Please call cmake with CMAKE_BUILD_TYPE=Release")

    IF(CMAKE_BUILD_TYPE MATCHES Debug)
      #message("Debug build.")
    ELSEIF(CMAKE_BUILD_TYPE MATCHES Release)
      #message("Release build.")
    ELSEIF(CMAKE_BUILD_TYPE MATCHES RELWITHDEBINFO)
      #message("Release with debug info build.")
    ELSE()
      message(ERROR "Unknown build type: ${CMAKE_BUILD_TYPE}  Please use one of Debug, Release, or RELWITHDEBINFO" )
    ENDIF()
endif()

# Select flags.
SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -rdynamic")
SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -rdynamic")

 

#############################################
#       Library/includes locations          #
#############################################

include_directories("${CMAKE_SOURCE_DIR}/libBDX")

include_directories("${CMAKE_SOURCE_DIR}/libBDXTests")

set(libOTe_Dir "${CMAKE_SOURCE_DIR}/../libOTe/")
include_directories(${libOTe_Dir})
#link_directories("${libOTe_Dir}/lib/")


# default location for miracl
set(Miracl_Dirs "${libOTe_Dir}/thirdparty/linux/miracl/")
include_directories("${Miracl_Dirs}") 

# default location for NTL
set(NTL_Dir "${CMAKE_SOURCE_DIR}/thirdparty/linux/ntl/")
include_directories("${NTL_Dir}/include")



# default location for Boost
set(BOOST_ROOT "${libOTe_Dir}/thirdparty/linux/boost/")


#############################################
#               Build libBDX                #
#############################################
add_subdirectory(libBDX)

#############################################
#           Build libBDX Tests              #
#############################################
add_subdirectory(libBDXTests)

#############################################
#              Build Frontend               #
#############################################
include_directories(${CMAKE_SOURCE_DIR})
file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/FrontEnd/*.cpp)
add_executable(frontend.exe ${SRC_FRONTEND})

#############################################
#            Install Frontend               #
#############################################
install (TARGETS frontend.exe DESTINATION bin)

#############################################
#            Link our libraries             #
#############################################

target_link_libraries(frontend.exe libBDXTests)
# other libs implicitly linked with libBDXTests


