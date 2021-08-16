# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

cmake_minimum_required(VERSION 3.16)
project(examples)
list(APPEND CMAKE_MODULE_PATH ./cmake)

find_package(BpfObject REQUIRED)

bpf_object(dwarf_walk ./src/bpf/dwarf_walk.bpf.c)
add_executable(dwarf_walk ./src/main.c)
target_link_libraries(dwarf_walk dwarf_walk_skel)
