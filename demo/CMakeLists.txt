cmake_minimum_required (VERSION 2.6)
project(DevFtGatherDemo)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../
)

aux_source_directory(../ SRC_LIST) # 搜索当前目录下的所有.cpp文件

add_executable(DevFtGatherDemo main.cpp ${SRC_LIST}) 

