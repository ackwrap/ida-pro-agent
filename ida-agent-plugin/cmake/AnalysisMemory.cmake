if(NOT (IDA_AGENT_ENABLE_AI OR IDA_AGENT_BUILD_AI_BACKEND))
    return()
endif()
add_library(ida_ai_analysis STATIC
    ai/analysis_memory/model.cpp
    ai/analysis_memory/store.cpp
    ai/analysis_memory/session.cpp
    ai/analysis_memory/tools.cpp
    ai/analysis_memory/workflows.cpp
    ai/agent_effect_digest.cpp)
target_include_directories(ida_ai_analysis PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(ida_ai_analysis PUBLIC cxx_std_17)
target_link_libraries(ida_ai_analysis PUBLIC ida_bridge_core nlohmann_json::nlohmann_json)
if(WIN32)
    target_link_libraries(ida_ai_analysis PUBLIC winsqlite3)
else()
    target_link_libraries(ida_ai_analysis PUBLIC ida_sqlite)
endif()
if(BUILD_TESTING)
    foreach(_test analysis_memory analysis_workflow)
        add_executable(ida_ai_${_test}_test tests/unit/ai/${_test}_test.cpp)
        target_link_libraries(ida_ai_${_test}_test PRIVATE ida_ai_analysis)
        add_test(NAME ida_ai_${_test} COMMAND ida_ai_${_test}_test)
        set_tests_properties(ida_ai_${_test} PROPERTIES TIMEOUT 30)
    endforeach()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME ida_ai_runtime_probe COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/ai/runtime_probe_test.py")
endif()
