# Find all .proto files in the current directory and its subdirectories
file(GLOB_RECURSE nfcap_protobuf "${CMAKE_CURRENT_SOURCE_DIR}/*.proto")
if (NOT nfcap_protobuf)
    message(FATAL_ERROR "No .proto files found in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Create directory for generated files
#set(GENERATED_PROTO_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
#file(MAKE_DIRECTORY ${GENERATED_PROTO_DIR})

# Add a gitignore file to the generated directory
#file(WRITE ${GENERATED_PROTO_DIR}/.gitignore "*")

#include_directories(${Protobuf_INCLUDE_DIRS})
#include_directories(${CMAKE_CURRENT_BINARY_DIR})

message(STATUS "Protobuf source files found: ${nfcap_protobuf}")

# Generate the protobuf files
foreach(PROTO_FILE ${nfcap_protobuf})
    protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS
        ${PROTO_FILE}
    )
    # Add the generated files to the list of sources
    list(APPEND PROTO_SOURCES ${PROTO_SRCS})
endforeach()

message(STATUS "Generated protobuf files: ${PROTO_SOURCES}")

file(GLOB_RECURSE WRAPPER_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cc")

add_library(nfcap_protobuf SHARED ${PROTO_SOURCES} ${WRAPPER_SRC})
set_target_properties(nfcap_protobuf PROPERTIES LINKER_LANGUAGE CXX)

target_include_directories(nfcap_protobuf PUBLIC ${Protobuf_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(nfcap_protobuf PUBLIC ${Protobuf_LIBRARIES})