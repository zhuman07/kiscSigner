cmake_minimum_required(VERSION 3.16.3)

project(kisc_sign)

add_executable(kisc_sign 
main.cpp 
${CMAKE_SOURCE_DIR}/src/loadTcsp.cpp 
${CMAKE_SOURCE_DIR}/src/signData.cpp)

target_link_libraries(kisc_sign restbed)

target_include_directories(kisc_sign PUBLIC ${CMAKE_SOURCE_DIR}/include)

find_package(glfw3 3.3 REQUIRED)
find_package(OpenGL REQUIRED)
target_include_directories(kisc_sign PUBLIC
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
                           $<INSTALL_INTERFACE:include>)
target_link_libraries(kisc_sign ${CMAKE_DL_LIBS})

set_property(TARGET kisc_sign PROPERTY CXX_STANDARD 17)