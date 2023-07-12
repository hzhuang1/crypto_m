cmake_minimum_required(VERSION 3.10)
project(ssl_asm_test C ASM)
add_executable(aes_01 aes_01.c cbc_aes.S cbc_aes_debug.S)
