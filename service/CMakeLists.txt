cmake_minimum_required (VERSION 3.18.4)

project(service)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
aux_source_directory(. DIR_SRCS)
add_executable(service ${DIR_SRCS})

target_link_libraries(service nl-3)
target_link_libraries(service nl-genl-3)

target_include_directories(service PRIVATE "/usr/include/libnl3")
include_directories("/usr/include/libnl3")