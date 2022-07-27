cmake_minimum_required(VERSION 3.12)

project(capmon VERSION 1.0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wpedantic -Wextra")

set(PROJECT_NAME_VERSION "${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}")

set(SRC_FILES
	capmon.c
	capabilities.c
	kprobes.c
	libcapmon.c
	)
list(TRANSFORM SRC_FILES PREPEND "${PROJECT_SOURCE_DIR}/src/")

configure_file(include/version.h.in include/version.h)

add_executable(capmon ${SRC_FILES})

target_include_directories(capmon PUBLIC
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_BINARY_DIR}/include
	)

install(TARGETS capmon
        CONFIGURATIONS Debug
        RUNTIME DESTINATION bin)
install(TARGETS capmon
        CONFIGURATIONS Release
        RUNTIME DESTINATION bin)

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
