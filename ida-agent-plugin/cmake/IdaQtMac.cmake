set(IDA_AGENT_QT_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/../../qt-sdk/qt-6.8.2-macos"
    CACHE PATH "Qt 6.8.2 macOS headers and configuration")
set(IDA_AGENT_IDA_QT_RUNTIME_DIR "${IDA_INSTALL_DIR}" CACHE PATH
    "IDA 9.4 macOS application bundle supplying QT-namespaced Qt 6.8.2")
option(IDA_AGENT_ENABLE_QT_AI_CONSOLE "Build the docked AI console" ON)
if(NOT IDA_AGENT_ENABLE_QT_AI_CONSOLE)
    message(FATAL_ERROR "macOS AI requires the Qt console; use IDA_AGENT_ENABLE_AI=OFF for a backend-only build")
endif()
set(IDA_AGENT_QT_MKSPEC macx-clang)
if(NOT EXISTS "${IDA_AGENT_QT_SDK_DIR}/include/QtCore/qconfig.h"
    OR NOT EXISTS "${IDA_AGENT_QT_SDK_DIR}/mkspecs/macx-clang/qplatformdefs.h")
    message(FATAL_ERROR "macOS Qt development headers are missing. See README-MACOS.md.")
endif()
file(STRINGS "${IDA_AGENT_QT_SDK_DIR}/include/QtCore/qconfig.h" _version
    REGEX "^#define QT_VERSION_STR \"[0-9.]+\"$")
if(NOT _version STREQUAL "#define QT_VERSION_STR \"6.8.2\"")
    message(FATAL_ERROR "macOS Qt development files must be exactly 6.8.2")
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(_qt_architectures ${CMAKE_OSX_ARCHITECTURES})
if(NOT _qt_architectures)
    set(_qt_architectures "${CMAKE_SYSTEM_PROCESSOR}")
endif()
execute_process(COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_LIST_DIR}/validate_ida_qt_macos.py"
    "${IDA_AGENT_IDA_QT_RUNTIME_DIR}" ${_qt_architectures}
    RESULT_VARIABLE _qt_result OUTPUT_VARIABLE _qt_output ERROR_VARIABLE _qt_error)
if(NOT _qt_result EQUAL 0)
    message(FATAL_ERROR "IDA macOS Qt validation failed: ${_qt_output}${_qt_error}")
endif()
set(IDA_AGENT_QT_IMPORT_LIBRARIES "")
foreach(_module Core Gui Widgets)
    add_library(ida_qt_${_module} SHARED IMPORTED)
    set_target_properties(ida_qt_${_module} PROPERTIES FRAMEWORK TRUE
        IMPORTED_LOCATION "${IDA_AGENT_IDA_QT_RUNTIME_DIR}/Contents/Frameworks/Qt${_module}.framework/Qt${_module}")
    list(APPEND IDA_AGENT_QT_IMPORT_LIBRARIES ida_qt_${_module})
endforeach()
message(STATUS "${_qt_output}")
