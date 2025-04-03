# Build all examples

#add_subdirectory(read_file)

# Examples list
set(EXAMPLES
    read_file
)

foreach(EXAMPLE ${EXAMPLES})
    # Name of the example
    set(EXAMPLE_NAME "${EXAMPLE}")

    # List all source files
    file(GLOB_RECURSE EXAMPLE_SOURCES "${EXAMPLE}/*.c")
    message(STATUS "Example sources: ${EXAMPLE_SOURCES}")

    # Add the example
    add_executable(${EXAMPLE_NAME} ${EXAMPLE_SOURCES})

    # Link the library pcap and nfcap
    target_link_libraries(${EXAMPLE_NAME} nfcap pcap)

    # Set the output directory
    set_target_properties(${EXAMPLE_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/examples)

    # Set the C++ standard
    set_target_properties(${EXAMPLE_NAME} PROPERTIES LINKER_LANGUAGE CXX)
endforeach()
