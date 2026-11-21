cmake_minimum_required(VERSION 3.21)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    project(vnm_filesystem_observation VERSION 1.0.0 LANGUAGES CXX)
    include(CTest)
endif()

add_subdirectory(filesystem_observation)
