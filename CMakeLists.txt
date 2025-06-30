cmake_minimum_required(VERSION 3.20)

set(PROJECT_NAME "nfcap")
set(PROJECT_DESCRIPTION "Flow-oriented network capture library")
set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 1)
set(PROJECT_VERSION_PATCH 0)
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")
set(PROJECT_VERSION_NAME "alpha")
set(PROJECT_AUTHOR "Gabin Noblet")
set(PROJECT_AUTHOR_EMAIL "gabin.noblet@gmail.com")

message(STATUS "Configuring ${PROJECT_NAME}")
message(STATUS "Author: ${PROJECT_AUTHOR} <${PROJECT_AUTHOR_EMAIL}>")
message(STATUS "Description: ${PROJECT_DESCRIPTION}")
message(STATUS "Version: ${PROJECT_VERSION}-${PROJECT_VERSION_NAME}")

project(${PROJECT_NAME} VERSION ${PROJECT_VERSION} DESCRIPTION ${PROJECT_DESCRIPTION} LANGUAGES C CXX)

include(CTest)
enable_testing()

# Configure the vscode snippets with project information
configure_file(templates/vscode.code-snippets.in ${CMAKE_SOURCE_DIR}/.vscode/lib${PROJECT_NAME}.code-snippets @ONLY)

# Configure the nglp-config.h file with project information
configure_file(templates/config.h.in ${CMAKE_SOURCE_DIR}/nfcap/config.h @ONLY)

# Includes
include_directories(nfcap)
include_directories(src)

# List all source files
file(GLOB_RECURSE SOURCES "src/*.c")
# Add *.cc files to the list of sources

# Compile protobuf files
find_package(Protobuf REQUIRED)
add_subdirectory(src/nfcap/protobuf)

# Add openssl
find_package(OpenSSL REQUIRED)

# Add the library
add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${PROJECT_NAME} nfcap_protobuf OpenSSL::SSL)
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "nfcap/nfcap.h")

# Set the output directory
set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

# Examples
add_subdirectory(examples)

# Tests
add_subdirectory(tests)