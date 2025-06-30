## Cmake for testing

find_program(MEMORYCHECK_COMMAND valgrind )
set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --track-origins=yes --leak-check=full" )

file(GLOB_RECURSE TEST_SOURCES "*.c")
message(STATUS "Test sources: ${TEST_SOURCES}")

foreach(TEST_SOURCE ${TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    message(STATUS "Adding test executable: ${TEST_NAME}")
    target_link_libraries(${TEST_NAME} nfcap pcap)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()