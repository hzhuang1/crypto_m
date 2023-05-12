cmake_minimum_required(VERSION 3.10)
project(ssl C)
add_executable(ssl_func ssl_func.c)
target_link_libraries(ssl_func crypto ssl)
