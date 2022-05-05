cmake_minimum_required(VERSION 3.23.1)

project(kisc_sign)

add_executable(kisc_sign 
main.cpp 
${CMAKE_SOURCE_DIR}/src/loadTcsp.cpp 
${CMAKE_SOURCE_DIR}/src/signData.cpp)

target_link_libraries(kisc_sign restbed)

target_include_directories(kisc_sign PUBLIC ${CMAKE_SOURCE_DIR}/include)

set_property(TARGET kisc_sign PROPERTY CXX_STANDARD 17)