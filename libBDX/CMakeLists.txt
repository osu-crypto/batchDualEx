
#project(libOTe)

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})

add_library(libBDX STATIC ${SRCS})


#############################################
#            Install                        #
#############################################

# install library
#install(TARGETS libOTe DESTINATION lib/${PROJECT_NAME})

# install headers
#install(DIRECTORY libOTe DESTINATION include FILES_MATCHING PATTERN "*.h")


###########################################################################
###########################################################################
#                        Link external libraries                          #
#                        -----------------------                          #
#                                                                         #
#  Define the expected location for miracl and boost.                     #
#  Boost will be found using the findBoost  module in CMake               #
#  It should look in the location specified and then look elsewhere       #
#                                                                         #
###########################################################################




find_library(
  LIBOTE_LIB
  NAMES libOTe
  HINTS "${libOTe_Dir}/lib/")

# if we cant fint it, throw an error
if(NOT LIBOTE_LIB)
  Message(${LIBOTE_LIB})
  message(FATAL_ERROR "Failed to find libOTe at ${libOTe_Dir}/lib/")
endif()

find_library(
  CRYPTOTOOLS_LIB
  NAMES cryptoTools
  HINTS "${libOTe_Dir}/lib/")

# if we cant fint it, throw an error
if(NOT LIBOTE_LIB)
  Message(${LIBOTE_LIB})
  message(FATAL_ERROR "Failed to find libOTe at ${libOTe_Dir}/lib/")
endif()

find_library(
  MIRACL_LIB
  NAMES miracl
  HINTS "${Miracl_Dirs}/miracl/source/")

# if we cant fint it, throw an error
if(NOT MIRACL_LIB)
  Message(${MIRACL_LIB})
  message(FATAL_ERROR "Failed to find miracl at " ${Miracl_Lib_Dirs})
endif()





find_library(
  NTL_LIB
  NAMES ntl
  HINTS "${NTL_Dir}/src/")

# if we cant fint it, throw an error
if(NOT NTL_LIB)
  Message(${NTL_LIB})
  message(FATAL_ERROR "Failed to find NTL at " ${NTL_Dir})
endif()


set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost  COMPONENTS system thread)

if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIR})
  #message( "Found Boost at ${Boost_LIBRARIES}")
else()
   message(FATAL_ERROR "Failed to find boost at " ${Boost_Lib_Dirs} " Need system thread")
endif()



target_link_libraries(libBDX ${LIBOTE_LIB})
target_link_libraries(libBDX ${CRYPTOTOOLS_LIB})
target_link_libraries(libBDX ${MIRACL_LIB})
target_link_libraries(libBDX ${Boost_LIBRARIES})
target_link_libraries(libBDX ${NTL_LIB})



#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)


