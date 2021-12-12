cmake_minimum_required (VERSION 3.18.4)

set(PROJECT_NAME hackernel)
project(${PROJECT_NAME})

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
aux_source_directory(. DIR_SRCS)
add_executable(${PROJECT_NAME} ${DIR_SRCS})

set(CMAKE_C_FLAGS "-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++20")

set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O2")

if (CMAKE_BUILD_TYPE MATCHES "Debug")
add_definitions(-DDEBUG)
endif()

include_directories("/usr/include/libnl3")

add_subdirectory(hknl)
add_subdirectory(heartbeat)
add_subdirectory(file)
add_subdirectory(process)
add_subdirectory(net)
add_subdirectory(ipc)
add_subdirectory(util)
add_subdirectory(dispatcher)

target_link_libraries(${PROJECT_NAME} hknl)
target_link_libraries(${PROJECT_NAME} heartbeat)
target_link_libraries(${PROJECT_NAME} file)
target_link_libraries(${PROJECT_NAME} process)
target_link_libraries(${PROJECT_NAME} net)
target_link_libraries(${PROJECT_NAME} ipc)
target_link_libraries(${PROJECT_NAME} util)
target_link_libraries(${PROJECT_NAME} dispatcher)

target_link_libraries(${PROJECT_NAME} nl-3)
target_link_libraries(${PROJECT_NAME} nl-genl-3)
target_link_libraries(${PROJECT_NAME} pthread)

