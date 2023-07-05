cmake_minimum_required (VERSION 3.18.4)

set(HACKERNEL hackernel)
project(${HACKERNEL})

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
aux_source_directory(. DIR_SRCS)
add_executable(${HACKERNEL} ${DIR_SRCS})

set(CMAKE_C_FLAGS "-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++20 -Wall -Werror")

set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O2")

if (CMAKE_BUILD_TYPE MATCHES "Debug")
add_definitions(-DDEBUG)
else()
add_custom_command(TARGET ${HACKERNEL} COMMAND ${CMAKE_STRIP} ${HACKERNEL})
endif()

include_directories("/usr/include/libnl3")

add_subdirectory(nlc)
add_subdirectory(heartbeat)
add_subdirectory(file)
add_subdirectory(process)
add_subdirectory(net)
add_subdirectory(ipc)
add_subdirectory(util)
add_subdirectory(dispatcher)

target_link_libraries(${HACKERNEL} nlc)
target_link_libraries(${HACKERNEL} heartbeat)
target_link_libraries(${HACKERNEL} file)
target_link_libraries(${HACKERNEL} process)
target_link_libraries(${HACKERNEL} net)
target_link_libraries(${HACKERNEL} ipc)
target_link_libraries(${HACKERNEL} util)
target_link_libraries(${HACKERNEL} dispatcher)

target_link_libraries(${HACKERNEL} nl-3)
target_link_libraries(${HACKERNEL} nl-genl-3)
target_link_libraries(${HACKERNEL} pthread)

