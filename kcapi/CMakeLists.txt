cmake_minimum_required(VERSION 3.10)
project(kcapi_test C)
add_executable(t01 kcapi_t01.c)
target_link_libraries(t01 kcapi ssl crypto)
