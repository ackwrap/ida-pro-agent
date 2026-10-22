# Opt-in: use IDA's actual Qt DLLs without loading or deploying the plugin.
option(IDA_AGENT_ENABLE_QT_RENDER_TESTS
    "Test the chat renderer against an installed Windows IDA Qt runtime" OFF)
if(NOT IDA_AGENT_ENABLE_QT_RENDER_TESTS)
    return()
endif()
if(NOT WIN32 OR NOT BUILD_TESTING OR NOT IDA_AGENT_ENABLE_QT_AI_CONSOLE)
    message(FATAL_ERROR "Qt renderer tests require Windows, BUILD_TESTING and the Qt AI console")
endif()
if(NOT IDA_AGENT_IDA_QT_RUNTIME_DIR)
    message(FATAL_ERROR "Qt renderer tests require IDA_AGENT_IDA_QT_RUNTIME_DIR (IDA 9.4 / Qt 6.8.2)")
endif()

add_executable(ida_ai_chat_message_view_test
    tests/unit/ai/chat_message_view_test.cpp
    ai/chat_message_view.cpp
    ai/chat_message_styles.cpp
    ai/chat_output_view.cpp
    ai/chat_render_budget.cpp
    ai/chat_code_highlight.cpp
    ai/chat_code_fences.cpp
    ai/chat_code_tokens.cpp
)
target_include_directories(ida_ai_chat_message_view_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(ida_ai_chat_message_view_test SYSTEM PRIVATE
    "${IDA_AGENT_QT_SDK_DIR}/include"
    "${IDA_AGENT_QT_SDK_DIR}/include/QtCore"
    "${IDA_AGENT_QT_SDK_DIR}/include/QtGui"
    "${IDA_AGENT_QT_SDK_DIR}/include/QtWidgets"
    "${IDA_AGENT_QT_SDK_DIR}/mkspecs/${IDA_AGENT_QT_MKSPEC}"
)
target_compile_features(ida_ai_chat_message_view_test PRIVATE cxx_std_17)
target_compile_definitions(ida_ai_chat_message_view_test PRIVATE
    QT_NAMESPACE=QT QT_CORE_LIB QT_GUI_LIB QT_WIDGETS_LIB QT_DLL QT_NO_DEBUG)
if(MSVC)
    target_compile_options(ida_ai_chat_message_view_test PRIVATE /GR /Zc:__cplusplus /permissive- /utf-8)
endif()
target_link_libraries(ida_ai_chat_message_view_test PRIVATE ${IDA_AGENT_QT_IMPORT_LIBRARIES})
add_test(NAME ida_ai_chat_message_view COMMAND ida_ai_chat_message_view_test)
set_tests_properties(ida_ai_chat_message_view PROPERTIES
    LABELS "qt;gui"
    TIMEOUT 60
    ENVIRONMENT "QT_PLUGIN_PATH=${IDA_AGENT_IDA_QT_RUNTIME_DIR}/plugins;QT_FATAL_WARNINGS=1"
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${IDA_AGENT_IDA_QT_RUNTIME_DIR}"
)
