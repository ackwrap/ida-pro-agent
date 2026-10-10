# Swift's public Network overlay provides URLSession proxy credentials. Compile
# each target slice separately because CMake's Swift driver is single-arch.
find_program(IDA_AGENT_XCRUN xcrun REQUIRED)
execute_process(COMMAND "${IDA_AGENT_XCRUN}" --sdk macosx --show-sdk-path
    OUTPUT_VARIABLE _mac_sdk OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
set(_proxy_arches ${CMAKE_OSX_ARCHITECTURES})
if(NOT _proxy_arches)
    set(_proxy_arches "${CMAKE_SYSTEM_PROCESSOR}")
endif()
set(_proxy_slices "")
foreach(_arch IN LISTS _proxy_arches)
    set(_slice "${CMAKE_CURRENT_BINARY_DIR}/libida_mac_proxy_${_arch}.a")
    add_custom_command(OUTPUT "${_slice}"
        COMMAND "${IDA_AGENT_XCRUN}" --sdk macosx swiftc -O -parse-as-library
            -emit-library -static -module-name IDAAgentMacProxy
            -target "${_arch}-apple-macos15.0" -sdk "${_mac_sdk}"
            "${CMAKE_CURRENT_SOURCE_DIR}/ai/macos_proxy.swift" -o "${_slice}"
        DEPENDS ai/macos_proxy.swift VERBATIM)
    list(APPEND _proxy_slices "${_slice}")
endforeach()
set(_proxy_library "${CMAKE_CURRENT_BINARY_DIR}/libida_mac_proxy.a")
add_custom_command(OUTPUT "${_proxy_library}"
    COMMAND lipo -create ${_proxy_slices} -output "${_proxy_library}"
    DEPENDS ${_proxy_slices} VERBATIM)
add_custom_target(ida_mac_proxy_build DEPENDS "${_proxy_library}")
add_library(ida_mac_proxy STATIC IMPORTED GLOBAL)
set_target_properties(ida_mac_proxy PROPERTIES IMPORTED_LOCATION "${_proxy_library}")
add_dependencies(ida_mac_proxy ida_mac_proxy_build)
target_link_directories(ida_mac_proxy INTERFACE "${_mac_sdk}/usr/lib/swift")
