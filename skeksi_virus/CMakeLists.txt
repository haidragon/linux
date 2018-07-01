cmake_minimum_required(VERSION 3.10)
project(skeksi_virus_master C)

set(CMAKE_C_STANDARD 11)

add_executable(skeksi_virus_master
        disinfect/disinfect.c
        virus.c)
