# Find all .proto files in the current directory and its subdirectories
file(GLOB_RECURSE nxcap_protobuf "${CMAKE_CURRENT_SOURCE_DIR}/*.proto")
if (NOT nxcap_protobuf)
    message(FATAL_ERROR "No .proto files found in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Generate the protobuf files
foreach(PROTO_FILE ${nxcap_protobuf})
    protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS
        ${PROTO_FILE}
    )
    # Add the generated files to the list of sources
    list(APPEND PROTO_SOURCES ${PROTO_SRCS})
endforeach()

file(GLOB_RECURSE WRAPPER_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cc")

add_library(nxcap_protobuf SHARED ${PROTO_SOURCES} ${WRAPPER_SRC})
set_target_properties(nxcap_protobuf PROPERTIES LINKER_LANGUAGE CXX)

target_include_directories(nxcap_protobuf PUBLIC ${Protobuf_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(nxcap_protobuf PUBLIC ${Protobuf_LIBRARIES})