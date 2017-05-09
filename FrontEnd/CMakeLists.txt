include_directories("${CMAKE_SOURCE_DIR}/FrontEnd")
include_directories("${CMAKE_SOURCE_DIR}/libBDXTests")

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
 