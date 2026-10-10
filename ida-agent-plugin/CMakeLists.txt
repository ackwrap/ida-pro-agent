cmake_minimum_required(VERSION 3.25)

# The SDK initializer must run before project() so it can select MSVC on Windows.
include("${CMAKE_CURRENT_LIST_DIR}/../ida-sdk/src/cmake/idasdk_init.cmake")

project(ida_agent_plugin LANGUAGES CXX)

# Keep build products outside the SDK submodule unless the caller chooses a deployment path.
if(NOT IDABIN)
    set(IDABIN "${CMAKE_BINARY_DIR}/ida-runtime" CACHE PATH "IDA runtime output directory")
endif()

find_package(idasdk REQUIRED)

option(IDA_AGENT_ENABLE_AI "Build the built-in AI agent and UI" ${WIN32})
option(IDA_AGENT_BUILD_AI_BACKEND "Build the independent non-UI Unix AI backend" OFF)
if(IDA_AGENT_ENABLE_AI)
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/IdaQt.cmake")
else()
    set(IDA_AGENT_ENABLE_QT_AI_CONSOLE OFF)
endif()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT WIN32)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
endif()
find_package(Threads REQUIRED)

include(FetchContent)
find_package(nlohmann_json 3.12.0 QUIET)
if(NOT nlohmann_json_FOUND)
    FetchContent_Declare(nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
        URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

add_library(ida_rpc_protocol STATIC
    bridge/rpc/address.cpp
    bridge/rpc/envelope.cpp
    bridge/rpc/error.cpp
    bridge/rpc/framing.cpp
    bridge/rpc/function_search_cursor.cpp
    bridge/rpc/list_cursor.cpp
    bridge/rpc/xref_query_cursor.cpp
    bridge/rpc/instance.cpp
    bridge/rpc/validation.cpp
)
target_include_directories(ida_rpc_protocol PUBLIC bridge/rpc)
target_compile_features(ida_rpc_protocol PUBLIC cxx_std_17)
target_link_libraries(ida_rpc_protocol PUBLIC nlohmann_json::nlohmann_json)
add_library(ida_semantic_analysis STATIC
    services/semantic_analysis/analysis.cpp
    services/semantic_analysis/callers.cpp
    services/semantic_analysis/request.cpp)
target_include_directories(ida_semantic_analysis PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ida_semantic_analysis PUBLIC ida_rpc_protocol)

if(NOT WIN32 AND NOT APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Only Windows, Linux and macOS are supported")
endif()

if(IDA_AGENT_ENABLE_AI AND WIN32)

set(IDA_AGENT_PROVIDER_MODEL_SOURCES ai/provider_settings_model.cpp ai/provider_url_win.cpp)
set(IDA_AGENT_HISTORY_STORE_SOURCES ai/chat_history_store.cpp ai/chat_history_path_win.cpp)

set(IDA_AGENT_STREAM_CLIENT_SOURCES
    ai/file_log.cpp
    ai/network_diagnostics.cpp
    ai/network_request_logger.cpp
    ai/stream_client.cpp
)
if(WIN32)
    list(APPEND IDA_AGENT_STREAM_CLIENT_SOURCES
        ai/stream_client_win.cpp
        ai/stream_client_win_sse.cpp
        ai/stream_client_win_sse_diagnostics.cpp
        ai/stream_client_win_websocket.cpp
    )
else()
    # Future macOS/Linux backends implement StreamClient without changing its public API.
    message(FATAL_ERROR "The AI stream client currently requires the Windows WinHTTP backend")
endif()

endif()

add_library(ida_bridge_core STATIC
    bridge/bridge.cpp
    bridge/instance/instance_identity_win.cpp
    bridge/rpc/dispatcher.cpp
)
if(WIN32)
    target_sources(ida_bridge_core PRIVATE
        bridge/crypto/secure_random_win.cpp
        bridge/instance/instance_paths_win.cpp
        bridge/instance/registry_file_win.cpp
        bridge/instance/secure_file_win.cpp
        bridge/transport/named_pipe_server_win.cpp)
    target_link_libraries(ida_bridge_core PUBLIC bcrypt advapi32 shell32)
else()
    target_sources(ida_bridge_core PRIVATE
        bridge/crypto/secure_random_linux.cpp
        bridge/instance/instance_paths_linux.cpp
        bridge/instance/registry_file_linux.cpp
        bridge/instance/runtime_linux.cpp
        bridge/instance/secure_file_linux.cpp
        bridge/transport/unix_socket_server_linux.cpp)
endif()
target_include_directories(ida_bridge_core PUBLIC bridge bridge/rpc)
target_compile_features(ida_bridge_core PUBLIC cxx_std_17)
target_link_libraries(ida_bridge_core PUBLIC ida_rpc_protocol Threads::Threads)

include(CTest)
if((CMAKE_SYSTEM_NAME STREQUAL "Linux" OR APPLE) AND (IDA_AGENT_BUILD_AI_BACKEND OR IDA_AGENT_ENABLE_AI))
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/LinuxAiBackend.cmake")
endif()

ida_add_plugin(ida_agent_plugin
    SOURCES
        plugin.cpp
        bridge/changeset_handlers.cpp
        bridge/composite_analysis.cpp
        bridge/composite_handlers.cpp
        bridge/debugger_handlers.cpp
        bridge/debugger_consent.cpp
        bridge/function_analysis_handlers.cpp
        bridge/function_graph_handlers.cpp
        bridge/inventory_handlers.cpp
        bridge/read_handlers.cpp
        bridge/readonly_analysis_handlers.cpp
        bridge/source_info_handlers.cpp
        bridge/annotation_handlers.cpp
        bridge/symbol_handlers.cpp
        bridge/decompiler_inspection_handlers.cpp
        bridge/query_handler_support.cpp
        bridge/semantic_analysis_handlers.cpp
        bridge/script_handlers.cpp
        bridge/search_handlers.cpp
        bridge/type_handlers.cpp
        bridge/workflow_handlers.cpp
        services/database_service.cpp
        services/changeset_annotations.cpp
        services/changeset_audit.cpp
        services/changeset_integer.cpp
        services/changeset_operands.cpp
        services/changeset_service.cpp
        services/changeset_state.cpp
        services/changeset_local.cpp
        services/changeset_types.cpp
        services/decompiler_service.cpp
        services/debugger_runtime.cpp
        services/debugger_service.cpp
        services/debugger_setup.cpp
        services/function_service.cpp
        services/function_graph_service.cpp
        services/inventory_text.cpp
        services/memory_service.cpp
        services/readonly_analysis_service.cpp
        services/source_info_service.cpp
        services/annotation_service.cpp
        services/symbol_demangle.cpp
        services/type_references.cpp
        services/decompiler_inspection_service.cpp
        services/debugger_inventory.cpp
        services/query_helpers.cpp
        services/semantic_analysis/microcode.cpp
        services/semantic_analysis/caller_service.cpp
        services/safe_regex.cpp
        services/search_assembly.cpp
        services/search_listing.cpp
        services/search_service.cpp
        services/search_results.cpp
        services/search_signature.cpp
        services/script_service.cpp
        services/string_service.cpp
        services/symbol_service.cpp
        services/type_inference.cpp
        services/type_json.cpp
        services/type_query.cpp
        services/type_service.cpp
        services/type_value.cpp
        services/type_xref.cpp
        services/xref_service.cpp
)

if(IDA_AGENT_ENABLE_AI)
    set(IDA_AGENT_AI_SOURCES
        ai/agent_effect_coordinator.cpp
        ai/agent_effect_digest.cpp
        ai/agent_effect_file_operations.cpp
        ai/agent_effect_service.cpp
        ai/agent_effect_service_operations.cpp
        ai/agent_file_service.cpp
        ai/agent_loop.cpp
        ai/agent_prompt.cpp
        ai/agent_tool_catalog.cpp
        ai/agent_tool_composites.cpp
        ai/agent_tool_definitions.cpp
        ai/agent_tool_definitions_extended.cpp
        ai/agent_tool_jobs.cpp
        ai/agent_tool_registry.cpp
        ai/agent_tool_registry_additional.cpp
        ai/agent_tool_transcript.cpp
        ai/agent_tool_services.cpp
        ai/agent_tool_services_extended.cpp
        ai/agent_ui_context.cpp
        ai/ai_menu.cpp
        ai/ai_menu_chat.cpp
        ai/ai_menu_context.cpp
        ai/ai_menu_selection.cpp
        ai/ai_menu_state.cpp
        ai/ai_menu_registry.cpp
        ai/chat_history_codec.cpp
        ${IDA_AGENT_HISTORY_STORE_SOURCES}
        ai/chat_command_line_edit.cpp
        ai/chat_context.cpp
        ai/chat_display_formatter.cpp
        ai/chat_output_menu.cpp
        ai/chat_output_view.cpp
        ai/chat_panel.cpp
        ai/chat_script_approval.cpp
        ai/chat_script_approval_dialog.cpp
        ai/chat_status_label.cpp
        ai/chat_transcript.cpp
        ai/cli_command.cpp
        ai/http_client.cpp
        ai/http_winhttp.cpp
        ai/jump_target_text.cpp
        ai/sse_parser.cpp
        ${IDA_AGENT_STREAM_CLIENT_SOURCES}
        ai/plugin_settings.cpp
        ai/plugin_settings_dialog.cpp
        ai/provider_chat.cpp
        ai/provider_chat_wire.cpp
        ai/provider_chat_decode.cpp
        ai/provider_chat_session.cpp
        ai/provider_client.cpp
        ai/provider_request.cpp
        ai/provider_settings_dialog.cpp
        ai/provider_settings/dialog_advanced.cpp
        ai/provider_settings/dialog_core.cpp
        ai/provider_settings/dialog_models.cpp
        ai/provider_settings/dialog_requests.cpp
        ${IDA_AGENT_PROVIDER_MODEL_SOURCES}
        ai/provider_settings_store.cpp
    )
    if(WIN32)
        target_link_libraries(ida_agent_plugin PRIVATE winhttp winsqlite3)
    else()
        list(REMOVE_ITEM IDA_AGENT_AI_SOURCES ${IDA_AGENT_AI_BACKEND_SOURCES}
            ai/http_winhttp.cpp ai/agent_file_service.cpp)
        list(APPEND IDA_AGENT_AI_SOURCES ai/agent_file_service_linux.cpp)
        target_link_libraries(ida_agent_plugin PRIVATE ida_ai_backend)
    endif()
    target_sources(ida_agent_plugin PRIVATE ${IDA_AGENT_AI_SOURCES})
endif()
target_compile_definitions(ida_agent_plugin PRIVATE IDA_AGENT_ENABLE_AI=$<BOOL:${IDA_AGENT_ENABLE_AI}>)

target_compile_features(ida_agent_plugin PRIVATE cxx_std_17)
set_target_properties(ida_agent_plugin PROPERTIES OUTPUT_NAME "ida-agent-plugin")
if(APPLE)
    # Resolve IDA and its Qt frameworks from the running application, never
    # embed the build machine's link-only framework directory in the plugin.
    set_target_properties(ida_agent_plugin PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "@executable_path;@executable_path/../Frameworks"
        INSTALL_RPATH_USE_LINK_PATH FALSE)
endif()
target_include_directories(ida_agent_plugin PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(ida_agent_plugin PRIVATE ida_bridge_core ida_semantic_analysis)
if(IDA_AGENT_ENABLE_QT_AI_CONSOLE)
    target_include_directories(ida_agent_plugin SYSTEM PRIVATE
        "${IDA_AGENT_QT_SDK_DIR}/include"
        "${IDA_AGENT_QT_SDK_DIR}/include/QtCore"
        "${IDA_AGENT_QT_SDK_DIR}/include/QtGui"
        "${IDA_AGENT_QT_SDK_DIR}/include/QtWidgets"
        "${IDA_AGENT_QT_SDK_DIR}/mkspecs/${IDA_AGENT_QT_MKSPEC}"
    )
    target_compile_definitions(ida_agent_plugin PRIVATE
        __QT__
        QT_NAMESPACE=QT
        QT_CORE_LIB
        QT_GUI_LIB
        QT_WIDGETS_LIB
        QT_DLL
        QT_THREAD_SUPPORT
        QT_NO_DEBUG
    )
    if(MSVC)
        target_compile_options(ida_agent_plugin PRIVATE /GR /Zc:__cplusplus /permissive-)
    endif()
    target_link_libraries(ida_agent_plugin PRIVATE ${IDA_AGENT_QT_IMPORT_LIBRARIES})
endif()

set(
    IDA_AGENT_USER_PLUGIN_DIR
    "$ENV{APPDATA}/Hex-Rays/IDA Pro/plugins"
    CACHE PATH
    "IDA user plugin directory used for automatic Debug deployment"
)
option(
    IDA_AGENT_DEPLOY_DEBUG_USER_PLUGIN
    "Copy the Debug plugin to the IDA user plugin directory after linking"
    ON
)
if(WIN32 AND IDA_AGENT_DEPLOY_DEBUG_USER_PLUGIN AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ida_agent_plugin POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDA_AGENT_USER_PLUGIN_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "$<TARGET_FILE:ida_agent_plugin>"
            "${IDA_AGENT_USER_PLUGIN_DIR}/$<TARGET_FILE_NAME:ida_agent_plugin>"
        COMMENT "Deploying Debug plugin to ${IDA_AGENT_USER_PLUGIN_DIR}"
        VERBATIM
    )
endif()

if(BUILD_TESTING)
    add_executable(ida_semantic_analysis_test
        tests/unit/semantic_analysis/analysis_test.cpp
    )
    target_link_libraries(ida_semantic_analysis_test PRIVATE ida_semantic_analysis)
    target_include_directories(ida_semantic_analysis_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(ida_semantic_analysis_test PRIVATE
        IDA_AGENT_PROTOCOL_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../protocol/testdata")
    add_test(NAME ida_semantic_analysis COMMAND ida_semantic_analysis_test)
    add_executable(ida_semantic_callers_test tests/unit/semantic_analysis/callers_test.cpp)
    target_link_libraries(ida_semantic_callers_test PRIVATE ida_semantic_analysis)
    target_compile_definitions(ida_semantic_callers_test PRIVATE
        IDA_AGENT_PROTOCOL_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../protocol/testdata")
    add_test(NAME ida_semantic_callers COMMAND ida_semantic_callers_test)
    foreach(_test_name address envelope framing instance string_search_options debugger_setup)
        add_executable(ida_rpc_${_test_name}_test
            tests/unit/rpc/${_test_name}_test.cpp
        )
        target_link_libraries(ida_rpc_${_test_name}_test PRIVATE ida_rpc_protocol)
        target_compile_definitions(ida_rpc_${_test_name}_test PRIVATE
            IDA_AGENT_PROTOCOL_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../protocol/testdata"
        )
        add_test(
            NAME ida_rpc_${_test_name}
            COMMAND ida_rpc_${_test_name}_test
        )
    endforeach()

    add_executable(ida_rpc_function_search_cursor_test
        tests/unit/rpc/function_search_cursor_test.cpp
    )
    target_link_libraries(ida_rpc_function_search_cursor_test PRIVATE ida_rpc_protocol)
    target_include_directories(ida_rpc_function_search_cursor_test PRIVATE tests/unit/rpc)
    target_compile_definitions(ida_rpc_function_search_cursor_test PRIVATE
        IDA_AGENT_PROTOCOL_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../protocol/testdata"
    )
    add_test(
        NAME ida_rpc_function_search_cursor
        COMMAND ida_rpc_function_search_cursor_test
    )

    add_executable(ida_rpc_xref_query_cursor_test
        tests/unit/rpc/xref_query_cursor_test.cpp
    )
    target_link_libraries(ida_rpc_xref_query_cursor_test PRIVATE ida_rpc_protocol)
    target_include_directories(ida_rpc_xref_query_cursor_test PRIVATE tests/unit/rpc)
    target_compile_definitions(ida_rpc_xref_query_cursor_test PRIVATE
        IDA_AGENT_PROTOCOL_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../protocol/testdata"
    )
    add_test(
        NAME ida_rpc_xref_query_cursor
        COMMAND ida_rpc_xref_query_cursor_test
    )

    add_executable(ida_rpc_list_cursor_test
        tests/unit/rpc/list_cursor_test.cpp
    )
    target_link_libraries(ida_rpc_list_cursor_test PRIVATE ida_rpc_protocol)
    target_include_directories(ida_rpc_list_cursor_test PRIVATE tests/unit/rpc services)
    target_compile_definitions(ida_rpc_list_cursor_test PRIVATE
        IDA_AGENT_PROTOCOL_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../protocol/testdata"
    )
    add_test(NAME ida_rpc_list_cursor COMMAND ida_rpc_list_cursor_test)

    add_executable(ida_bridge_dispatcher_test
        tests/unit/bridge/dispatcher_test.cpp
    )
    target_link_libraries(ida_bridge_dispatcher_test PRIVATE ida_bridge_core)
    add_test(NAME ida_bridge_dispatcher COMMAND ida_bridge_dispatcher_test)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR APPLE)
        add_executable(ida_bridge_unix_socket_test tests/unit/bridge/unix_socket_test.cpp)
        target_link_libraries(ida_bridge_unix_socket_test PRIVATE ida_bridge_core)
        add_test(NAME ida_bridge_unix_socket COMMAND ida_bridge_unix_socket_test)
        set_tests_properties(ida_bridge_unix_socket PROPERTIES TIMEOUT 15)
    endif()

    if(WIN32)
    add_executable(ida_bridge_lifecycle_test
        tests/unit/bridge/bridge_lifecycle_test.cpp
    )
    add_executable(ida_bridge_debugger_consent_test
        tests/unit/bridge/debugger_consent_test.cpp
    )
    target_link_libraries(ida_bridge_debugger_consent_test PRIVATE ida_bridge_core)
    add_test(NAME ida_bridge_debugger_consent COMMAND ida_bridge_debugger_consent_test)
    target_link_libraries(ida_bridge_lifecycle_test PRIVATE ida_bridge_core)
    add_test(NAME ida_bridge_lifecycle COMMAND ida_bridge_lifecycle_test)
    set_tests_properties(ida_bridge_lifecycle PROPERTIES TIMEOUT 10)

    add_executable(ida_bridge_named_pipe_server_test
        tests/unit/bridge/named_pipe_server_test.cpp
    )
    target_link_libraries(ida_bridge_named_pipe_server_test PRIVATE ida_bridge_core)
    add_test(NAME ida_bridge_named_pipe_server COMMAND ida_bridge_named_pipe_server_test)
    set_tests_properties(ida_bridge_named_pipe_server PROPERTIES TIMEOUT 30)

    endif()

    add_executable(ida_service_safe_regex_test
        tests/unit/services/safe_regex_test.cpp
        services/safe_regex.cpp
    )
    target_include_directories(ida_service_safe_regex_test PRIVATE services tests/unit/services)
    target_compile_features(ida_service_safe_regex_test PRIVATE cxx_std_17)
    add_test(NAME ida_service_safe_regex COMMAND ida_service_safe_regex_test)

    add_executable(ida_service_changeset_integer_test
        tests/unit/services/changeset_integer_test.cpp
        services/changeset_integer.cpp
    )
    target_include_directories(ida_service_changeset_integer_test PRIVATE services tests/unit/services)
    target_compile_features(ida_service_changeset_integer_test PRIVATE cxx_std_17)
    add_test(NAME ida_service_changeset_integer COMMAND ida_service_changeset_integer_test)

    if(IDA_AGENT_ENABLE_AI AND WIN32)
    add_executable(ida_ai_provider_settings_model_test
        tests/unit/ai/provider_settings_model_test.cpp
        ${IDA_AGENT_PROVIDER_MODEL_SOURCES}
    )
    target_include_directories(ida_ai_provider_settings_model_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_provider_settings_model_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_provider_settings_model_test PRIVATE winhttp)
    add_test(NAME ida_ai_provider_settings_model COMMAND ida_ai_provider_settings_model_test)

    add_executable(ida_ai_agent_tool_registry_test
        tests/unit/ai/agent_prompt_test.cpp
        tests/unit/ai/agent_file_registry_test.cpp
        tests/unit/semantic_analysis/agent_tools_test.cpp
        tests/unit/ai/agent_tool_registry_test.cpp
        tests/unit/ai/agent_string_refresh_test.cpp
        tests/unit/ai/agent_debugger_registry_test.cpp
        ai/agent_prompt.cpp
        ai/agent_tool_definitions.cpp
        ai/agent_tool_definitions_extended.cpp
        ai/agent_tool_jobs.cpp
        ai/agent_tool_registry.cpp
        ai/agent_tool_registry_additional.cpp
    )
    target_include_directories(ida_ai_agent_tool_registry_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_agent_tool_registry_test PRIVATE cxx_std_17)
    target_compile_definitions(ida_ai_agent_tool_registry_test PRIVATE
        IDA_AGENT_AGENT_TOOL_REGISTRY_TESTING
    )
    target_link_libraries(ida_ai_agent_tool_registry_test PRIVATE nlohmann_json::nlohmann_json ida_semantic_analysis)
    add_test(NAME ida_ai_agent_tool_registry COMMAND ida_ai_agent_tool_registry_test)

    add_executable(ida_ai_agent_loop_test
        tests/unit/ai/agent_loop_test.cpp
        ai/agent_effect_coordinator.cpp
        ai/agent_loop.cpp
        ai/agent_prompt.cpp
        ai/agent_tool_catalog.cpp
        ai/agent_tool_definitions.cpp
        ai/agent_tool_definitions_extended.cpp
        ai/agent_tool_jobs.cpp
        ai/agent_tool_registry.cpp
        ai/agent_tool_registry_additional.cpp
        ai/provider_chat.cpp
        ai/provider_chat_wire.cpp
        ai/provider_request.cpp
        ${IDA_AGENT_PROVIDER_MODEL_SOURCES}
    )
    target_include_directories(ida_ai_agent_loop_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_agent_loop_test PRIVATE cxx_std_17)
    target_compile_definitions(ida_ai_agent_loop_test PRIVATE
        IDA_AGENT_AGENT_TOOL_REGISTRY_TESTING=1
    )
    target_link_libraries(ida_ai_agent_loop_test PRIVATE
        ida_semantic_analysis
        nlohmann_json::nlohmann_json
        winhttp
    )
    add_test(NAME ida_ai_agent_loop COMMAND ida_ai_agent_loop_test)

    add_executable(ida_ai_agent_effect_coordinator_test
        tests/unit/ai/agent_effect_coordinator_test.cpp
        ai/agent_effect_coordinator.cpp
    )
    target_include_directories(ida_ai_agent_effect_coordinator_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_agent_effect_coordinator_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_agent_effect_coordinator_test PRIVATE nlohmann_json::nlohmann_json)
    add_test(NAME ida_ai_agent_effect_coordinator COMMAND ida_ai_agent_effect_coordinator_test)

    add_executable(ida_ai_chat_script_approval_test
        tests/unit/ai/chat_script_approval_test.cpp
        ai/chat_script_approval.cpp
    )
    target_include_directories(ida_ai_chat_script_approval_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_chat_script_approval_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_chat_script_approval_test PRIVATE nlohmann_json::nlohmann_json)
    add_test(NAME ida_ai_chat_script_approval COMMAND ida_ai_chat_script_approval_test)

    add_executable(ida_ai_agent_effect_service_test
        tests/unit/ai/agent_effect_service_test.cpp
        tests/unit/ai/agent_debugger_setup_test.cpp
        ai/agent_effect_coordinator.cpp
        ai/agent_effect_digest.cpp
        ai/agent_effect_file_operations.cpp
        ai/agent_effect_service.cpp
        ai/agent_effect_service_operations.cpp
    )
    target_include_directories(ida_ai_agent_effect_service_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_agent_effect_service_test PRIVATE cxx_std_17)
    target_compile_definitions(ida_ai_agent_effect_service_test PRIVATE
        IDA_AGENT_AGENT_EFFECT_SERVICE_TESTING
    )
    target_link_libraries(ida_ai_agent_effect_service_test PRIVATE nlohmann_json::nlohmann_json)
    add_test(NAME ida_ai_agent_effect_service COMMAND ida_ai_agent_effect_service_test)

    add_executable(ida_ai_agent_file_service_test
        tests/unit/ai/agent_file_service_test.cpp
        ai/agent_effect_digest.cpp
        ai/agent_file_service.cpp
    )
    target_include_directories(ida_ai_agent_file_service_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_agent_file_service_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_agent_file_service_test PRIVATE nlohmann_json::nlohmann_json)
    add_test(NAME ida_ai_agent_file_service COMMAND ida_ai_agent_file_service_test)

    add_executable(ida_ai_jump_target_text_test
        tests/unit/ai/jump_target_text_test.cpp
        ai/jump_target_text.cpp
    )
    target_include_directories(ida_ai_jump_target_text_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_jump_target_text_test PRIVATE cxx_std_17)
    add_test(NAME ida_ai_jump_target_text COMMAND ida_ai_jump_target_text_test)

    add_executable(ida_ai_provider_client_test
        tests/unit/ai/provider_client_test.cpp
        ai/http_client.cpp
        ai/http_winhttp.cpp
        ai/provider_client.cpp
        ai/provider_request.cpp
        ${IDA_AGENT_PROVIDER_MODEL_SOURCES}
    )
    target_include_directories(ida_ai_provider_client_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_provider_client_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_provider_client_test PRIVATE
        nlohmann_json::nlohmann_json
        winhttp
    )
    add_test(NAME ida_ai_provider_client COMMAND ida_ai_provider_client_test)

    add_executable(ida_ai_provider_client_loopback_test
        tests/unit/ai/provider_client_loopback_test.cpp
        ai/http_client.cpp
        ai/http_winhttp.cpp
        ai/provider_client.cpp
        ai/provider_request.cpp
        ${IDA_AGENT_PROVIDER_MODEL_SOURCES}
    )
    target_include_directories(ida_ai_provider_client_loopback_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_provider_client_loopback_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_provider_client_loopback_test PRIVATE
        nlohmann_json::nlohmann_json
        winhttp
        ws2_32
    )
    add_test(NAME ida_ai_provider_client_loopback COMMAND ida_ai_provider_client_loopback_test)
    set_tests_properties(ida_ai_provider_client_loopback PROPERTIES TIMEOUT 30)

    add_executable(ida_ai_provider_chat_test
        tests/unit/ai/provider_chat_test.cpp
        ai/provider_chat.cpp
        ai/provider_chat_wire.cpp
        ai/provider_chat_decode.cpp
        ai/provider_request.cpp
        ${IDA_AGENT_PROVIDER_MODEL_SOURCES}
    )
    target_include_directories(ida_ai_provider_chat_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_provider_chat_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_provider_chat_test PRIVATE
        nlohmann_json::nlohmann_json
        winhttp
    )
    add_test(NAME ida_ai_provider_chat COMMAND ida_ai_provider_chat_test)

    add_executable(ida_ai_provider_chat_session_test
        tests/unit/ai/provider_chat_session_test.cpp
        ai/provider_chat_decode.cpp
        ai/provider_chat_session.cpp
        ai/sse_parser.cpp
        ${IDA_AGENT_STREAM_CLIENT_SOURCES}
    )
    target_include_directories(ida_ai_provider_chat_session_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_provider_chat_session_test PRIVATE cxx_std_17)
    target_compile_definitions(ida_ai_provider_chat_session_test PRIVATE
        IDA_AGENT_PROVIDER_CHAT_SESSION_TESTING
        IDA_AGENT_STREAM_CLIENT_TESTING
    )
    target_link_libraries(ida_ai_provider_chat_session_test PRIVATE
        bcrypt
        nlohmann_json::nlohmann_json
        winhttp
        ws2_32
    )
    add_test(NAME ida_ai_provider_chat_session COMMAND ida_ai_provider_chat_session_test)
    set_tests_properties(ida_ai_provider_chat_session PROPERTIES TIMEOUT 60)

    add_executable(ida_ai_http_client_test
        tests/unit/ai/http_client_test.cpp
        ai/http_client.cpp
        ai/http_winhttp.cpp
    )
    target_include_directories(ida_ai_http_client_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_http_client_test PRIVATE cxx_std_17)
    target_compile_definitions(ida_ai_http_client_test PRIVATE IDA_AGENT_HTTP_CLIENT_TESTING)
    target_link_libraries(ida_ai_http_client_test PRIVATE winhttp)
    add_test(NAME ida_ai_http_client COMMAND ida_ai_http_client_test)

    add_executable(ida_ai_sse_parser_test
        tests/unit/ai/sse_parser_test.cpp
        ai/sse_parser.cpp
    )
    target_include_directories(ida_ai_sse_parser_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_sse_parser_test PRIVATE cxx_std_17)
    add_test(NAME ida_ai_sse_parser COMMAND ida_ai_sse_parser_test)

    add_executable(ida_ai_stream_client_test
        tests/unit/ai/stream_client_test.cpp
        ai/sse_parser.cpp
        ${IDA_AGENT_STREAM_CLIENT_SOURCES}
    )
    target_include_directories(ida_ai_stream_client_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_stream_client_test PRIVATE cxx_std_17)
    target_compile_definitions(ida_ai_stream_client_test PRIVATE
        IDA_AGENT_STREAM_CLIENT_TESTING
    )
    target_link_libraries(ida_ai_stream_client_test PRIVATE
        nlohmann_json::nlohmann_json
        winhttp
    )
    add_test(NAME ida_ai_stream_client COMMAND ida_ai_stream_client_test)

    add_executable(ida_ai_stream_client_loopback_test
        tests/unit/ai/stream_client_loopback_test.cpp
        ai/sse_parser.cpp
        ${IDA_AGENT_STREAM_CLIENT_SOURCES}
    )
    target_include_directories(ida_ai_stream_client_loopback_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_stream_client_loopback_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_stream_client_loopback_test PRIVATE
        bcrypt
        nlohmann_json::nlohmann_json
        winhttp
        ws2_32
    )
    add_test(NAME ida_ai_stream_client_loopback COMMAND ida_ai_stream_client_loopback_test)
    set_tests_properties(ida_ai_stream_client_loopback PROPERTIES TIMEOUT 30)

    add_executable(ida_ai_provider_settings_store_test
        tests/unit/ai/provider_settings_store_test.cpp
        ai/provider_settings_store.cpp
        ${IDA_AGENT_PROVIDER_MODEL_SOURCES}
    )
    target_include_directories(ida_ai_provider_settings_store_test PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/bridge"
    )
    target_compile_features(ida_ai_provider_settings_store_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_provider_settings_store_test PRIVATE
        ida_bridge_core
        nlohmann_json::nlohmann_json
        winhttp
    )
    add_test(NAME ida_ai_provider_settings_store COMMAND ida_ai_provider_settings_store_test)

    add_executable(ida_ai_plugin_settings_test
        tests/unit/ai/plugin_settings_test.cpp
        ai/plugin_settings.cpp
    )
    target_include_directories(ida_ai_plugin_settings_test PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/bridge"
    )
    target_compile_features(ida_ai_plugin_settings_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_plugin_settings_test PRIVATE
        ida_bridge_core
        nlohmann_json::nlohmann_json
    )
    add_test(NAME ida_ai_plugin_settings COMMAND ida_ai_plugin_settings_test)

    add_executable(ida_ai_chat_ui_model_test
        tests/unit/ai/chat_ui_model_test.cpp
        ai/chat_context.cpp
        ai/chat_display_formatter.cpp
        ai/chat_transcript.cpp
        ai/cli_command.cpp
    )
    target_include_directories(ida_ai_chat_ui_model_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_chat_ui_model_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_chat_ui_model_test PRIVATE nlohmann_json::nlohmann_json)
    add_test(NAME ida_ai_chat_ui_model COMMAND ida_ai_chat_ui_model_test)

    add_executable(ida_ai_chat_history_codec_test
        tests/unit/ai/chat_history_codec_test.cpp
        ai/agent_tool_transcript.cpp
        ai/chat_history_codec.cpp
        ai/chat_transcript.cpp
    )
    target_include_directories(ida_ai_chat_history_codec_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_features(ida_ai_chat_history_codec_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_chat_history_codec_test PRIVATE nlohmann_json::nlohmann_json)
    add_test(NAME ida_ai_chat_history_codec COMMAND ida_ai_chat_history_codec_test)

    add_executable(ida_ai_chat_history_store_test
        tests/unit/ai/chat_history_store_test.cpp
        ${IDA_AGENT_HISTORY_STORE_SOURCES}
        ai/chat_history_codec.cpp
        ai/chat_transcript.cpp
    )
    target_include_directories(ida_ai_chat_history_store_test PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/bridge"
    )
    target_compile_features(ida_ai_chat_history_store_test PRIVATE cxx_std_17)
    target_link_libraries(ida_ai_chat_history_store_test PRIVATE
        ida_bridge_core
        nlohmann_json::nlohmann_json
        winsqlite3
    )
    add_test(NAME ida_ai_chat_history_store COMMAND ida_ai_chat_history_store_test)
    endif()

endif()

option(IDA_AGENT_ENABLE_INTEGRATION_TESTS "Enable slow tests that launch a real IDA instance" OFF)
set(IDA_INSTALL_DIR "" CACHE PATH "IDA installation used for integration tests")
option(IDA_AGENT_ENABLE_GUI_TESTS "Test the AI panel in a real Unix IDA GUI session" OFF)
if(IDA_AGENT_ENABLE_GUI_TESTS)
    if((NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT APPLE) OR NOT IDA_AGENT_ENABLE_AI
        OR NOT IDA_AGENT_ENABLE_QT_AI_CONSOLE OR NOT BUILD_TESTING)
        message(FATAL_ERROR "GUI tests require Linux/macOS, BUILD_TESTING and the Qt AI console")
    endif()
    set(_panel_ida_dir "${IDA_AGENT_IDA_QT_RUNTIME_DIR}")
    set(_panel_test ida_linux_panel_integration)
    if(APPLE)
        set(_panel_ida_dir "${IDA_INSTALL_DIR}")
        set(_panel_test ida_macos_panel_integration)
    endif()
    add_test(NAME ${_panel_test}
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_linux_panel.py"
            --ida-dir "${_panel_ida_dir}" --plugin "$<TARGET_FILE:ida_agent_plugin>")
    set_tests_properties(${_panel_test} PROPERTIES
        TIMEOUT 240 RUN_SERIAL TRUE LABELS "integration;slow;gui")
endif()

if(APPLE AND BUILD_TESTING AND IDA_AGENT_ENABLE_INTEGRATION_TESTS)
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/MacIntegrationTests.cmake")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND BUILD_TESTING AND IDA_AGENT_ENABLE_INTEGRATION_TESTS)
    if(NOT EXISTS "${IDA_INSTALL_DIR}/idat")
        message(FATAL_ERROR "IDA_INSTALL_DIR must contain the Linux idat executable")
    endif()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    find_program(GO_EXECUTABLE go REQUIRED)
    set(_linux_gateway "${CMAKE_BINARY_DIR}/integration-gateway/ida-mcp")
    add_custom_target(ida_linux_gateway ALL
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/integration-gateway"
        COMMAND "${GO_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}/../ida-mcp"
            build -o "${_linux_gateway}" .
        BYPRODUCTS "${_linux_gateway}"
        VERBATIM)
    add_test(NAME ida_linux_mcp_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_linux_smoke.py"
            --ida-dir "${IDA_INSTALL_DIR}" --plugin "$<TARGET_FILE:ida_agent_plugin>"
            --gateway "${_linux_gateway}")
    set_tests_properties(ida_linux_mcp_integration PROPERTIES TIMEOUT 240 LABELS "integration;slow" RUN_SERIAL TRUE)
    add_test(NAME ida_linux_functional_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_linux_smoke.py"
            --ida-dir "${IDA_INSTALL_DIR}" --plugin "$<TARGET_FILE:ida_agent_plugin>"
            --gateway "${_linux_gateway}" --functional)
    set_tests_properties(ida_linux_functional_integration PROPERTIES TIMEOUT 240 LABELS "integration;slow" RUN_SERIAL TRUE)
    add_test(NAME ida_linux_recovery_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_linux_smoke.py"
            --ida-dir "${IDA_INSTALL_DIR}" --plugin "$<TARGET_FILE:ida_agent_plugin>"
            --gateway "${_linux_gateway}" --crash-recovery)
    set_tests_properties(ida_linux_recovery_integration PROPERTIES TIMEOUT 240 LABELS "integration;slow" RUN_SERIAL TRUE)
    # Test-only C entry point, never registered as RPC or deployed to the user.
    ida_add_plugin(ida_linux_debugger_driver
        SOURCES tests/integration/debugger_driver.cpp
            bridge/debugger_handlers.cpp bridge/query_handler_support.cpp
            services/debugger_service.cpp services/debugger_setup.cpp
            services/debugger_runtime.cpp services/debugger_inventory.cpp services/query_helpers.cpp)
    target_include_directories(ida_linux_debugger_driver PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(ida_linux_debugger_driver PRIVATE ida_bridge_core)
    target_compile_features(ida_linux_debugger_driver PRIVATE cxx_std_17)
    add_executable(ida_linux_debugger_sample tests/integration/linux_debugger_sample.cpp)
    target_compile_options(ida_linux_debugger_sample PRIVATE -O0 -fno-inline -fno-pie)
    target_link_options(ida_linux_debugger_sample PRIVATE -no-pie)
    target_link_libraries(ida_linux_debugger_sample PRIVATE Threads::Threads)
    add_test(NAME ida_linux_debugger_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_linux_debugger.py"
            --ida-dir "${IDA_INSTALL_DIR}" --driver "$<TARGET_FILE:ida_linux_debugger_driver>"
            --sample "$<TARGET_FILE:ida_linux_debugger_sample>")
    set_tests_properties(ida_linux_debugger_integration PROPERTIES
        TIMEOUT 180 RUN_SERIAL TRUE LABELS "integration;slow;debugger")
    foreach(_optimization O0 O2)
        add_executable(ida_linux_semantic_sample_${_optimization} tests/integration/semantic_sample.cpp)
        target_compile_options(ida_linux_semantic_sample_${_optimization} PRIVATE
            -${_optimization} -fno-inline -fno-optimize-sibling-calls -fno-pie)
        target_link_options(ida_linux_semantic_sample_${_optimization} PRIVATE -no-pie)
        add_test(NAME ida_linux_semantic_integration_${_optimization}
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_semantic_analysis.py"
                --ida-dir "${IDA_INSTALL_DIR}" --plugin "$<TARGET_FILE:ida_agent_plugin>"
                --sample "$<TARGET_FILE:ida_linux_semantic_sample_${_optimization}>")
        set_tests_properties(ida_linux_semantic_integration_${_optimization} PROPERTIES
            TIMEOUT 180 RUN_SERIAL TRUE LABELS "integration;slow;semantic")
    endforeach()
endif()
if(WIN32 AND BUILD_TESTING AND IDA_AGENT_ENABLE_INTEGRATION_TESTS)
    if(NOT IDA_INSTALL_DIR)
        message(FATAL_ERROR "IDA_INSTALL_DIR is required when integration tests are enabled")
    endif()
    find_program(POWERSHELL_EXECUTABLE NAMES pwsh REQUIRED)
    find_program(GO_EXECUTABLE NAMES go REQUIRED)
    find_package(Python3 3 REQUIRED COMPONENTS Interpreter)
    if(NOT EXISTS "${IDA_INSTALL_DIR}/idat.exe")
        message(FATAL_ERROR "idat.exe was not found under IDA_INSTALL_DIR=${IDA_INSTALL_DIR}")
    endif()
    # This driver links the production handlers/services without exposing a
    # permission bypass in the shipping plugin or any network/Pipe endpoint.
    ida_add_plugin(ida_debugger_integration_driver
        SOURCES tests/integration/debugger_driver.cpp
            bridge/debugger_handlers.cpp bridge/query_handler_support.cpp
            services/debugger_service.cpp services/debugger_setup.cpp
            services/debugger_runtime.cpp services/debugger_inventory.cpp
            services/query_helpers.cpp)
    target_include_directories(ida_debugger_integration_driver PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(ida_debugger_integration_driver PRIVATE ida_bridge_core)
    target_compile_features(ida_debugger_integration_driver PRIVATE cxx_std_17)
    add_executable(ida_debugger_integration_sample tests/integration/debugger_sample.cpp)
    target_compile_options(ida_debugger_integration_sample PRIVATE /Od /Ob0)
    add_test(NAME ida_debugger_integration
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_debugger_idat.py"
            --ida-dir "${IDA_INSTALL_DIR}" --driver "$<TARGET_FILE:ida_debugger_integration_driver>"
            --sample "$<TARGET_FILE:ida_debugger_integration_sample>")
    set_tests_properties(ida_debugger_integration PROPERTIES
        TIMEOUT 180 RUN_SERIAL TRUE LABELS "integration;slow;debugger")
    foreach(_optimization Od O2)
        add_executable(ida_semantic_sample_${_optimization} tests/integration/semantic_sample.cpp)
        target_compile_options(ida_semantic_sample_${_optimization} PRIVATE /${_optimization} /Ob0)
        add_test(NAME ida_semantic_integration_${_optimization}
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_semantic_analysis.py"
                --ida-dir "${IDA_INSTALL_DIR}" --plugin "$<TARGET_FILE:ida_agent_plugin>"
                --sample "$<TARGET_FILE:ida_semantic_sample_${_optimization}>")
        set_tests_properties(ida_semantic_integration_${_optimization} PROPERTIES
            TIMEOUT 180 RUN_SERIAL TRUE LABELS "integration;slow;semantic")
    endforeach()
    add_test(
        NAME ida_agent_plugin_lifecycle
        COMMAND
            "${POWERSHELL_EXECUTABLE}"
            -NoProfile
            -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_plugin_lifecycle.ps1"
            -IdaDir "${IDA_INSTALL_DIR}"
            -PluginPath "$<TARGET_FILE:ida_agent_plugin>"
            -PythonExecutable "${Python3_EXECUTABLE}"
    )
    set_tests_properties(ida_agent_plugin_lifecycle PROPERTIES TIMEOUT 180 LABELS "integration;slow")

    add_test(
        NAME ida_agent_gateway_ping
        COMMAND
            "${POWERSHELL_EXECUTABLE}"
            -NoProfile
            -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/run_gateway_ping.ps1"
            -IdaDir "${IDA_INSTALL_DIR}"
            -PluginPath "$<TARGET_FILE:ida_agent_plugin>"
            -GatewayDir "${CMAKE_CURRENT_SOURCE_DIR}/../ida-mcp"
            -GoExecutable "${GO_EXECUTABLE}"
    )
    set_tests_properties(
        ida_agent_gateway_ping
        PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE LABELS "integration;slow"
    )
endif()
