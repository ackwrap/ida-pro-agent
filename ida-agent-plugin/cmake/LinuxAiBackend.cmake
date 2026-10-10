# The backend is independently usable without Qt or IDA UI initialization.
if(APPLE)
    include("${CMAKE_CURRENT_LIST_DIR}/MacAiDependencies.cmake")
    set(IDA_AGENT_PROVIDER_URL_SOURCE ai/provider_url_macos.cpp)
    set(IDA_AGENT_HISTORY_PATH_SOURCE ai/chat_history_path_macos.mm)
    set(IDA_AGENT_HTTP_SOURCES ai/http_macos.cpp ai/macos_url_session.mm)
    set(IDA_AGENT_STREAM_SOURCES ai/stream_client_linux.cpp ai/stream_client_macos.cpp)
else()
    include("${CMAKE_CURRENT_LIST_DIR}/LinuxAiDependencies.cmake")
    set(IDA_AGENT_NETWORK_LIBRARIES CURL::libcurl)
    set(IDA_AGENT_PROVIDER_URL_SOURCE ai/provider_url_linux.cpp)
    set(IDA_AGENT_HISTORY_PATH_SOURCE ai/chat_history_path_linux.cpp)
    set(IDA_AGENT_HTTP_SOURCES ai/http_curl.cpp)
    set(IDA_AGENT_STREAM_SOURCES ai/stream_client_linux.cpp
        ai/stream_client_linux_sse.cpp ai/stream_client_linux_websocket.cpp)
endif()
set(IDA_AGENT_AI_BACKEND_SOURCES
    ai/plugin_settings.cpp
    ai/provider_settings_model.cpp
    ai/provider_settings_store.cpp
    ${IDA_AGENT_PROVIDER_URL_SOURCE}
    ai/chat_history_store.cpp
    ai/chat_history_writer.cpp
    ${IDA_AGENT_HISTORY_PATH_SOURCE}
    ai/chat_history_codec.cpp
    ai/chat_transcript.cpp
    ai/agent_tool_transcript.cpp
    ai/http_client.cpp
    ${IDA_AGENT_HTTP_SOURCES}
    ai/provider_client.cpp
    ai/provider_request.cpp
    ai/sse_parser.cpp
    ai/stream_client.cpp
    ${IDA_AGENT_STREAM_SOURCES}
    ai/file_log.cpp
    ai/network_request_logger.cpp
    ai/network_diagnostics.cpp
    ai/provider_chat.cpp
    ai/provider_chat_wire.cpp
    ai/provider_chat_decode.cpp
    ai/provider_chat_session.cpp)
add_library(ida_ai_backend STATIC ${IDA_AGENT_AI_BACKEND_SOURCES})
target_include_directories(ida_ai_backend PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(ida_ai_backend PUBLIC ida_bridge_core ${IDA_AGENT_NETWORK_LIBRARIES} ida_sqlite)
target_compile_features(ida_ai_backend PUBLIC cxx_std_17)

if(BUILD_TESTING)
    include("${CMAKE_CURRENT_LIST_DIR}/LinuxAiPanelTests.cmake")
    foreach(_test provider_settings_model provider_settings_store plugin_settings chat_history_codec chat_history_store chat_history_writer linux_storage provider_client sse_parser provider_chat stream_client)
        add_executable(ida_ai_${_test}_test tests/unit/ai/${_test}_test.cpp)
        target_link_libraries(ida_ai_${_test}_test PRIVATE ida_ai_backend)
        add_test(NAME ida_ai_${_test} COMMAND ida_ai_${_test}_test)
        set_tests_properties(ida_ai_${_test} PROPERTIES TIMEOUT 30)
    endforeach()
    add_executable(ida_ai_provider_chat_session_test tests/unit/ai/provider_chat_session_test.cpp
        ai/provider_chat_session.cpp)
    foreach(_test stream_client provider_chat_session)
        # Every translation unit that defines Impl sees the same test-only layout.
        target_sources(ida_ai_${_test}_test PRIVATE ${IDA_AGENT_STREAM_SOURCES})
        target_compile_definitions(ida_ai_${_test}_test PRIVATE IDA_AGENT_STREAM_CLIENT_TESTING)
    endforeach()
    target_compile_definitions(ida_ai_provider_chat_session_test PRIVATE
        IDA_AGENT_STREAM_CLIENT_TESTING IDA_AGENT_PROVIDER_CHAT_SESSION_TESTING)
    target_link_libraries(ida_ai_provider_chat_session_test PRIVATE ida_ai_backend)
    add_test(NAME ida_ai_provider_chat_session COMMAND ida_ai_provider_chat_session_test)
    set_tests_properties(ida_ai_provider_chat_session PROPERTIES TIMEOUT 45)
    # Keep test-only methods out of the production backend library.
    add_executable(ida_ai_http_client_test tests/unit/ai/http_client_test.cpp ai/http_client.cpp ${IDA_AGENT_HTTP_SOURCES})
    target_include_directories(ida_ai_http_client_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_definitions(ida_ai_http_client_test PRIVATE IDA_AGENT_HTTP_CLIENT_TESTING)
    target_compile_features(ida_ai_http_client_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_http_client_test PRIVATE ${IDA_AGENT_NETWORK_LIBRARIES} Threads::Threads)
    add_test(NAME ida_ai_http_client COMMAND ida_ai_http_client_test)
    set_tests_properties(ida_ai_http_client PROPERTIES TIMEOUT 30)
    find_package(Python3 3 REQUIRED COMPONENTS Interpreter)
    find_program(OPENSSL_EXECUTABLE openssl REQUIRED)
    execute_process(COMMAND "${Python3_EXECUTABLE}" -c "import websockets.legacy.server"
        RESULT_VARIABLE _websockets_result ERROR_QUIET)
    if(NOT _websockets_result EQUAL 0)
        message(FATAL_ERROR "Linux stream tests require python3-websockets (legacy server API).")
    endif()
    add_executable(ida_ai_linux_stream_test tests/unit/ai/linux_stream_test.cpp)
    # Observe queue completion without consuming events; match every Impl translation unit.
    target_sources(ida_ai_linux_stream_test PRIVATE ${IDA_AGENT_STREAM_SOURCES})
    target_compile_definitions(ida_ai_linux_stream_test PRIVATE IDA_AGENT_STREAM_CLIENT_TESTING)
    target_link_libraries(ida_ai_linux_stream_test PRIVATE ida_ai_backend)
    add_test(NAME ida_ai_linux_stream COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/ai/run_linux_stream.py" "$<TARGET_FILE:ida_ai_linux_stream_test>"
        "${OPENSSL_EXECUTABLE}")
    set_tests_properties(ida_ai_linux_stream PROPERTIES TIMEOUT 70)
    add_executable(ida_ai_linux_http_test tests/unit/ai/linux_http_test.cpp)
    target_link_libraries(ida_ai_linux_http_test PRIVATE ida_ai_backend)
    add_test(NAME ida_ai_linux_http COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/ai/run_linux_http.py" "$<TARGET_FILE:ida_ai_linux_http_test>"
        "${OPENSSL_EXECUTABLE}")
    set_tests_properties(ida_ai_linux_http PROPERTIES TIMEOUT 60)
endif()
