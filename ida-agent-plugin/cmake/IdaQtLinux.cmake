set(IDA_AGENT_QT_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/../../qt-sdk/qt-6.8.2-linux"
    CACHE PATH "Qt 6.8.2 Linux headers and configuration")
set(IDA_AGENT_IDA_QT_RUNTIME_DIR "${IDA_INSTALL_DIR}" CACHE PATH
    "IDA 9.4 Linux installation supplying QT-namespaced Qt 6.8.2")
option(IDA_AGENT_ENABLE_QT_AI_CONSOLE "Build the docked AI console" ON)
if(NOT IDA_AGENT_ENABLE_QT_AI_CONSOLE)
    message(FATAL_ERROR "Linux AI requires the Qt console; use IDA_AGENT_ENABLE_AI=OFF for a backend-only build")
endif()
set(IDA_AGENT_QT_MKSPEC linux-g++)
if(NOT EXISTS "${IDA_AGENT_QT_SDK_DIR}/include/QtCore/qconfig.h"
    OR NOT EXISTS "${IDA_AGENT_QT_SDK_DIR}/mkspecs/linux-g++/qplatformdefs.h")
    message(FATAL_ERROR "Linux Qt headers are missing. See README-LINUX.md: IDA_AGENT_QT_SDK_DIR")
endif()
file(STRINGS "${IDA_AGENT_QT_SDK_DIR}/include/QtCore/qconfig.h" _version
    REGEX "^#define QT_VERSION_STR \"[0-9.]+\"$")
if(NOT _version STREQUAL "#define QT_VERSION_STR \"6.8.2\"")
    message(FATAL_ERROR "Linux Qt development files must be exactly 6.8.2")
endif()
include(CheckIncludeFileCXX)
check_include_file_cxx("GL/gl.h" IDA_AGENT_HAVE_GL_HEADERS)
if(NOT IDA_AGENT_HAVE_GL_HEADERS)
    message(FATAL_ERROR "Qt Widgets requires OpenGL headers; install libgl-dev on Ubuntu")
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
execute_process(COMMAND "${CMAKE_COMMAND}" -E env
    "LD_LIBRARY_PATH=${IDA_AGENT_IDA_QT_RUNTIME_DIR}"
    "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/validate_ida_qt_linux.py"
    "${IDA_AGENT_IDA_QT_RUNTIME_DIR}"
    RESULT_VARIABLE _qt_result OUTPUT_VARIABLE _qt_output ERROR_VARIABLE _qt_error)
if(NOT _qt_result EQUAL 0)
    message(FATAL_ERROR "IDA Linux Qt validation failed: ${_qt_output}${_qt_error}")
endif()
set(IDA_AGENT_QT_IMPORT_LIBRARIES "")
foreach(_module Core Gui Widgets)
    add_library(ida_qt_${_module} SHARED IMPORTED)
    set_target_properties(ida_qt_${_module} PROPERTIES
        IMPORTED_LOCATION "${IDA_AGENT_IDA_QT_RUNTIME_DIR}/libQt6${_module}.so.6")
    list(APPEND IDA_AGENT_QT_IMPORT_LIBRARIES ida_qt_${_module})
endforeach()
message(STATUS "${_qt_output}")
