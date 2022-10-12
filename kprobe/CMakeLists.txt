# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

cmake_minimum_required(VERSION 3.16)
project(examples)

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf)

include(ProcessorCount)
ProcessorCount(N)

# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND COMMAND make -j${N}
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND COMMAND make -j${N}
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
  DEPENDS libbpf
)

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_BINARY_DIR}/bpftool/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

# Create an executable for each application
#file(GLOB apps *.bpf.c)
#foreach(app ${apps})
#get_filename_component(app_stem ${app} NAME_WE)
set(kprobe bootstrap)

# Build object skeleton and depend skeleton on libbpf build
bpf_object(${kprobe} ${kprobe}.bpf.c)
add_dependencies(${kprobe}_skel bpftool)
add_dependencies(${kprobe}_skel libbpf)

add_executable(${kprobe} ${kprobe}.c)
target_link_libraries(${kprobe} ${kprobe}_skel)
#endforeach()
