cmake_minimum_required(VERSION 3.20)
project(email LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(email INTERFACE)
add_library(email::email ALIAS email)

target_include_directories(email INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

if (MSVC)
  target_compile_options(email INTERFACE /W4 /permissive-)
else()
  target_compile_options(email INTERFACE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
enable_testing()

add_executable(email_basic_test tests/test_basic.cpp)
target_link_libraries(email_basic_test PRIVATE email::email)
add_test(NAME email.basic COMMAND email_basic_test)
