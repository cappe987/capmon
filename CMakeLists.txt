# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2020 Facebook

cmake_minimum_required(VERSION 3.16)
project(examples)

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake)

# Create directory beforehand, allows parallelization
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf)

# Output .skel.h into generated include directory
set(SKEL_DIR include)
# Output .bpf.o into bpfobj/. Create the dir if not exists
set(BPFOBJECT_DIR obj)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${BPFOBJECT_DIR})

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
bpf_object(${kprobe} src/${kprobe}.bpf.c)
add_dependencies(${kprobe}_skel bpftool)
add_dependencies(${kprobe}_skel libbpf)

#add_executable(${kprobe} ${kprobe}.c)
#endforeach()

###################
###### CAPMON #####
###################
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

cmake_minimum_required(VERSION 3.12)

project(capmon VERSION 1.2)

set(CMAKE_C_FLAGS
	"${CMAKE_C_FLAGS} -Wall -Wpedantic -Wextra -Wno-gnu-zero-variadic-macro-arguments"
	)

set(PROJECT_NAME_VERSION "${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}")

set(SRC_FILES
	capmon.c
	capabilities.c
	kprobes.c
	libcapmon.c
	monitor.c
	)
list(TRANSFORM SRC_FILES PREPEND "${PROJECT_SOURCE_DIR}/src/")

configure_file(include/version.h.in include/version.h)

add_executable(capmon ${SRC_FILES})

target_include_directories(capmon PUBLIC
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_BINARY_DIR}/include
	${PROJECT_BINARY_DIR}/bpf
	)

target_link_libraries(capmon ${kprobe}_skel)

install(TARGETS capmon
        CONFIGURATIONS Debug
        RUNTIME DESTINATION bin)
install(TARGETS capmon
        CONFIGURATIONS Release
        RUNTIME DESTINATION bin)

#add_custom_target(libbpf
	#COMMAND 
	#mkdir "-p" "${PROJECT_BINARY_DIR}/bpf"
	#COMMAND
	#cp 
	#"${PROJECT_SOURCE_DIR}/bpftool/libbpf/src/*"
	#"${PROJECT_BINARY_DIR}/bpf"
	#)

#add_custom_target(bpf
	#WORKING_DIRECTORY
	#"${PROJECT_SOURCE_DIR}/src/bpf"
	#COMMAND
	#make
	#)

add_custom_target(tar
	COMMAND 
	mkdir "-p" "${PROJECT_NAME_VERSION}"
	COMMAND
	cp 
	"-r"
	"../CMakeLists.txt"
	"../LICENSE"
	"../README.md"
	"../.gitignore"
	"../include"
	"../src"
	"${PROJECT_NAME_VERSION}"
	COMMAND 
	tar 
	"-cvzf" 
	"${PROJECT_NAME_VERSION}.tar.gz"
	"${PROJECT_NAME_VERSION}/"
	)

set_directory_properties(
	PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
	"${PROJECT_BINARY_DIR}/${PROJECT_NAME_VERSION}.tar.gz"
	)

