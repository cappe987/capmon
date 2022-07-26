cmake_minimum_required(VERSION 3.12)

project(capmon VERSION 1.0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wpedantic -Wextra")


set(SRC_FILES
	capmon.c
	capabilities.c
	kprobes.c
	libcapmon.c
	)
list(TRANSFORM SRC_FILES PREPEND "${PROJECT_SOURCE_DIR}/src/")

add_executable(capmon ${SRC_FILES})

target_include_directories(capmon PRIVATE
  ${PROJECT_SOURCE_DIR}/include
)

install(TARGETS capmon
        CONFIGURATIONS Debug
        RUNTIME DESTINATION bin)
install(TARGETS capmon
        CONFIGURATIONS Release
        RUNTIME DESTINATION bin)
