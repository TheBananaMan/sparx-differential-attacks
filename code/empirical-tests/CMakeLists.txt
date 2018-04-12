# ----------------------------------------------------------
# Common
# ----------------------------------------------------------

cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

# ----------------------------------------------------------
# Building apps
# ----------------------------------------------------------

# Project name
project(sparx-tests)

# Store variables
set(PROJECT_CHECK_RESULTS_DIR check)
set(PROJECT_SOURCE_DIR src)
set(UTILS_SOURCE_DIR ${PROJECT_SOURCE_DIR}/utils)
set(CIPHERS_SOURCE_DIR ${PROJECT_SOURCE_DIR}/ciphers)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
SET(INCLUDE_DIRECTORIES include)

# Add include paths
include_directories(${INCLUDE_DIRECTORIES})

# Stores all executables in src folder into variable SOURCES
file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/*.cpp")
file(GLOB UTILS_SOURCES "${UTILS_SOURCE_DIR}/*.cpp")
file(GLOB CIPHERS_SOURCES "${CIPHERS_SOURCE_DIR}/*.cpp")

# Compile flags
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W -Wall -Wextra -pedantic -std=c++11 -march=native -O3")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -ggdb3 -DDEBUG -fsanitize=undefined -fsanitize=alignment -ftrapv -fno-omit-frame-pointer -fno-optimize-sibling-calls")
# -Wconversion -Wsign-conversion -Werror

if(NOT CMAKE_BUILD_TYPE) 
    set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)

# Logging
message("Using build type ${CMAKE_BUILD_TYPE}")

# Include pthread
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Builds all files "xx.cpp" in sources folder to executable "xx"
foreach(source_file ${SOURCES})
    # Replace cpp from "xx.cpp" to get executable name "xx"
    string(REPLACE ".cpp" "" filename_without_extension ${source_file})
    string(REPLACE "${CMAKE_SOURCE_DIR}/${PROJECT_SOURCE_DIR}/" "" filename_without_extension ${filename_without_extension})

    add_executable(${filename_without_extension} ${source_file} ${UTILS_SOURCES} ${CIPHERS_SOURCES})
    
    # Link against pthread
    target_link_libraries(${filename_without_extension} Threads::Threads)
endforeach(source_file ${SOURCES})

# ----------------------------------------------------------
# Special build targets for checking, tidying, formatting
# ----------------------------------------------------------

# Check
add_custom_target(
    clang-check
    COMMAND /usr/bin/clang-check
    ${SOURCES}
    --
    -I${INCLUDE_DIRECTORIES}
    -std=c++11
)

# Tidy
add_custom_target(
    clang-tidy
    COMMAND /usr/bin/clang-tidy
    ${SOURCES}
    --
    -std=c++11
    -I${INCLUDE_DIRECTORIES}
)

# Format
add_custom_target(
    clang-format
    COMMAND /usr/bin/clang-format
    -style=file
    -i
    ${SOURCES}
    -I${INCLUDE_DIRECTORIES}
)
