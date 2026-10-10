# macOS uses NSURLSession / Security.framework; no curl or OpenSSL dependency.
if(CMAKE_OSX_DEPLOYMENT_TARGET AND CMAKE_OSX_DEPLOYMENT_TARGET VERSION_LESS "15.0")
    message(FATAL_ERROR "The macOS AI build requires a deployment target of 15.0 or later")
endif()
enable_language(C OBJCXX)
set(CMAKE_OBJCXX_STANDARD 17)
set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)
set(CMAKE_OBJCXX_EXTENSIONS OFF)
set(CMAKE_OBJCXX_VISIBILITY_PRESET hidden)
include("${CMAKE_CURRENT_LIST_DIR}/MacProxy.cmake")
find_library(IDA_AGENT_FOUNDATION Foundation REQUIRED)
find_library(IDA_AGENT_SECURITY Security REQUIRED)
find_library(IDA_AGENT_CFNETWORK CFNetwork REQUIRED)
find_library(IDA_AGENT_NETWORK Network REQUIRED)
set(IDA_AGENT_NETWORK_LIBRARIES
    "${IDA_AGENT_FOUNDATION}" "${IDA_AGENT_SECURITY}" "${IDA_AGENT_CFNETWORK}"
    "${IDA_AGENT_NETWORK}" ida_mac_proxy)
set_source_files_properties(ai/macos_url_session.mm ai/chat_history_path_macos.mm
    PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
include("${CMAKE_CURRENT_LIST_DIR}/SqliteDependency.cmake")
