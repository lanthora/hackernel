cmake_minimum_required (VERSION 3.18.4)

set(PROJECT_NAME hackernel)
project(${PROJECT_NAME})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
aux_source_directory(. DIR_SRCS)
add_executable(${PROJECT_NAME} ${DIR_SRCS})

set(CMAKE_C_FLAGS "-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")

set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O2")

set_property(TARGET hackernel PROPERTY CXX_STANDARD 20)

target_link_libraries(${PROJECT_NAME} nl-3)
target_link_libraries(${PROJECT_NAME} nl-genl-3)
target_link_libraries(${PROJECT_NAME} pthread)

target_include_directories(${PROJECT_NAME} PRIVATE "/usr/include/libnl3")
include_directories("/usr/include/libnl3")
