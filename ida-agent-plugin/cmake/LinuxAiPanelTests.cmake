# Exercise shared Agent and UI models against the Linux backend.
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
target_link_libraries(ida_ai_agent_tool_registry_test PRIVATE ida_ai_backend)

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
)
target_include_directories(ida_ai_agent_loop_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(ida_ai_agent_loop_test PRIVATE cxx_std_17)
target_compile_definitions(ida_ai_agent_loop_test PRIVATE
    IDA_AGENT_AGENT_TOOL_REGISTRY_TESTING=1
)
target_link_libraries(ida_ai_agent_loop_test PRIVATE
    ida_semantic_analysis
    nlohmann_json::nlohmann_json
)
add_test(NAME ida_ai_agent_loop COMMAND ida_ai_agent_loop_test)
target_link_libraries(ida_ai_agent_loop_test PRIVATE ida_ai_backend)

add_executable(ida_ai_agent_effect_coordinator_test
    tests/unit/ai/agent_effect_coordinator_test.cpp
    ai/agent_effect_coordinator.cpp
)
target_include_directories(ida_ai_agent_effect_coordinator_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(ida_ai_agent_effect_coordinator_test PRIVATE cxx_std_17)
target_link_libraries(ida_ai_agent_effect_coordinator_test PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME ida_ai_agent_effect_coordinator COMMAND ida_ai_agent_effect_coordinator_test)
target_link_libraries(ida_ai_agent_effect_coordinator_test PRIVATE ida_ai_backend)

add_executable(ida_ai_chat_script_approval_test
    tests/unit/ai/chat_script_approval_test.cpp
    ai/chat_script_approval.cpp
)
target_include_directories(ida_ai_chat_script_approval_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(ida_ai_chat_script_approval_test PRIVATE cxx_std_17)
target_link_libraries(ida_ai_chat_script_approval_test PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME ida_ai_chat_script_approval COMMAND ida_ai_chat_script_approval_test)
target_link_libraries(ida_ai_chat_script_approval_test PRIVATE ida_ai_backend)

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
target_link_libraries(ida_ai_agent_effect_service_test PRIVATE ida_ai_backend)

add_executable(ida_ai_agent_file_service_test
    tests/unit/ai/agent_file_service_test.cpp
    ai/agent_effect_digest.cpp
    ai/agent_file_service_linux.cpp
)
target_include_directories(ida_ai_agent_file_service_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(ida_ai_agent_file_service_test PRIVATE cxx_std_17)
target_link_libraries(ida_ai_agent_file_service_test PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME ida_ai_agent_file_service COMMAND ida_ai_agent_file_service_test)
target_link_libraries(ida_ai_agent_file_service_test PRIVATE ida_ai_backend)

add_executable(ida_ai_jump_target_text_test
    tests/unit/ai/jump_target_text_test.cpp
    ai/jump_target_text.cpp
)
target_include_directories(ida_ai_jump_target_text_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(ida_ai_jump_target_text_test PRIVATE cxx_std_17)
add_test(NAME ida_ai_jump_target_text COMMAND ida_ai_jump_target_text_test)
target_link_libraries(ida_ai_jump_target_text_test PRIVATE ida_ai_backend)

add_executable(ida_ai_chat_ui_model_test
    tests/unit/ai/chat_ui_model_test.cpp
    ai/chat_context.cpp
    ai/chat_display_formatter.cpp
    ai/cli_command.cpp
)
target_include_directories(ida_ai_chat_ui_model_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(ida_ai_chat_ui_model_test PRIVATE cxx_std_17)
target_link_libraries(ida_ai_chat_ui_model_test PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME ida_ai_chat_ui_model COMMAND ida_ai_chat_ui_model_test)
target_link_libraries(ida_ai_chat_ui_model_test PRIVATE ida_ai_backend)
