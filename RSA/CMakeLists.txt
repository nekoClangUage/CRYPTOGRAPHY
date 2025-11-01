cmake_minimum_required(VERSION 3.10)
project(BIT_6)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GMPXX REQUIRED gmpxx)

include_directories(include ${GMPXX_INCLUDE_DIRS})

add_executable(main src/main.cpp src/rsa.cpp)

target_link_libraries(main ${GMPXX_LIBRARIES})
