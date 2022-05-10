cmake_minimum_required(VERSION 3.16.3)

#set(CMAKE_TOOLCHAIN_FILE "C:/src/vcpkg/scripts/buildsystems/vcpkg.cmake")
#set(VCPKG_TARGET_TRIPLET "x64-windows")

project(kisc_sign)

add_executable(kisc_sign 
main.cpp 
${CMAKE_SOURCE_DIR}/src/loadTcsp.cpp 
${CMAKE_SOURCE_DIR}/src/signData.cpp)

#include(C:/src/vcpkg/scripts/buildsystems/vcpkg.cmake)
#find_package(restbed)
target_link_libraries(kisc_sign restbed)

target_include_directories(kisc_sign PUBLIC ${CMAKE_SOURCE_DIR}/include)

set_property(TARGET kisc_sign PROPERTY CXX_STANDARD 17)