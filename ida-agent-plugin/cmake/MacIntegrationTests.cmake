if(NOT EXISTS "${IDA_INSTALL_DIR}/idat")
    message(FATAL_ERROR "IDA_INSTALL_DIR must point to IDA.app/Contents/MacOS")
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(GO_EXECUTABLE go REQUIRED)
set(_mac_gateway "${CMAKE_BINARY_DIR}/integration-gateway/ida-mcp")
add_custom_target(ida_macos_gateway ALL
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/integration-gateway"
    COMMAND "${GO_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}/../ida-mcp"
        build -o "${_mac_gateway}" .
    BYPRODUCTS "${_mac_gateway}" VERBATIM)
foreach(_mode mcp functional recovery)
    set(_arguments "")
    if(_mode STREQUAL "functional")
        set(_arguments --functional)
    elseif(_mode STREQUAL "recovery")
        set(_arguments --crash-recovery)
    endif()
    add_test(NAME ida_macos_${_mode}_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_linux_smoke.py"
            --ida-dir "${IDA_INSTALL_DIR}" --plugin "$<TARGET_FILE:ida_agent_plugin>"
            --gateway "${_mac_gateway}" ${_arguments})
    set_tests_properties(ida_macos_${_mode}_integration PROPERTIES
        TIMEOUT 240 LABELS "integration;slow" RUN_SERIAL TRUE)
endforeach()
