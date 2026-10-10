# IDA supplies Qt at runtime on every supported platform.
if(APPLE)
    include("${CMAKE_CURRENT_LIST_DIR}/IdaQtMac.cmake")
    return()
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include("${CMAKE_CURRENT_LIST_DIR}/IdaQtLinux.cmake")
    return()
endif()
set(IDA_AGENT_QT_MKSPEC win32-msvc)
set(IDA_AGENT_QT_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/../../qt-sdk/qt-6.8.2-win"
    CACHE PATH "Qt 6.8.2 headers and configuration for the IDA AI console")
set(IDA_AGENT_IDA_QT_RUNTIME_DIR "" CACHE PATH
    "Optional IDA 9.4 installation to regenerate Qt imports instead of using the SDK libraries")
option(IDA_AGENT_ENABLE_QT_AI_CONSOLE
    "Build the docked AI console with an independent input line" ON)

if(NOT IDA_AGENT_ENABLE_QT_AI_CONSOLE)
    return()
endif()

# Qt-owned objects cross the module boundary, including in Debug builds.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()

if(NOT EXISTS "${IDA_AGENT_QT_SDK_DIR}/include/QtCore/qconfig.h")
    message(FATAL_ERROR
        "Qt 6.8.2 development files are required at IDA_AGENT_QT_SDK_DIR: ${IDA_AGENT_QT_SDK_DIR}")
endif()
file(STRINGS "${IDA_AGENT_QT_SDK_DIR}/include/QtCore/qconfig.h"
    _ida_agent_qt_version_line REGEX "^#define QT_VERSION_STR \"[0-9.]+\"$")
if(NOT _ida_agent_qt_version_line STREQUAL "#define QT_VERSION_STR \"6.8.2\"")
    message(FATAL_ERROR
        "Qt development files must be exactly 6.8.2: ${_ida_agent_qt_version_line}")
endif()

set(IDA_AGENT_QT_IMPORT_LIBRARIES "")
if(NOT IDA_AGENT_IDA_QT_RUNTIME_DIR)
    # These official QT-namespaced imports are tracked in the pinned SDK.
    # Linking needs neither an IDA installation nor stock Qt runtime DLLs.
    set(_ida_qt_import_dir "${IDASDK}/lib/x64_win_qt")
    foreach(_qt_module Core Gui Widgets)
        set(_ida_qt_import "${_ida_qt_import_dir}/Qt6${_qt_module}.lib")
        if(NOT EXISTS "${_ida_qt_import}")
            message(FATAL_ERROR
                "IDA SDK Qt import library is missing: ${_ida_qt_import}. "
                "Initialize the pinned SDK with git submodule update --init ida-sdk.")
        endif()
        list(APPEND IDA_AGENT_QT_IMPORT_LIBRARIES "${_ida_qt_import}")
    endforeach()
    message(STATUS "Using IDA SDK Qt import libraries: ${_ida_qt_import_dir}")
    return()
endif()

# Explicit local override retains host version and namespace validation.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
foreach(_qt_module Core Gui Widgets)
    if(NOT EXISTS "${IDA_AGENT_IDA_QT_RUNTIME_DIR}/Qt6${_qt_module}.dll")
        message(FATAL_ERROR
            "IDA Qt runtime is missing Qt6${_qt_module}.dll under: ${IDA_AGENT_IDA_QT_RUNTIME_DIR}")
    endif()
endforeach()
if(NOT EXISTS "${IDA_AGENT_IDA_QT_RUNTIME_DIR}/ida.exe")
    message(FATAL_ERROR
        "IDA 9.4 executable is missing under: ${IDA_AGENT_IDA_QT_RUNTIME_DIR}")
endif()
get_filename_component(_msvc_bin_dir "${CMAKE_AR}" DIRECTORY)
set(_dumpbin "${_msvc_bin_dir}/dumpbin.exe")
if(NOT EXISTS "${_dumpbin}")
    message(FATAL_ERROR "dumpbin.exe was not found beside CMAKE_AR: ${_dumpbin}")
endif()
set(_ida_qt_import_dir "${CMAKE_BINARY_DIR}/ida-qt-imports")
foreach(_qt_module Core Gui Widgets)
    set(_ida_qt_import "${_ida_qt_import_dir}/Qt6${_qt_module}.lib")
    execute_process(
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_LIST_DIR}/generate_ida_qt_import_lib.py"
            --dumpbin "${_dumpbin}"
            --lib "${CMAKE_AR}"
            --dll "${IDA_AGENT_IDA_QT_RUNTIME_DIR}/Qt6${_qt_module}.dll"
            --output "${_ida_qt_import}"
            --expected-version 6.8.2
            --expected-namespace QT
            --host-executable "${IDA_AGENT_IDA_QT_RUNTIME_DIR}/ida.exe"
            --expected-host-version 9.4
        RESULT_VARIABLE _ida_qt_import_result
    )
    if(NOT _ida_qt_import_result EQUAL 0)
        message(FATAL_ERROR "Failed to generate IDA Qt import library for ${_qt_module}")
    endif()
    list(APPEND IDA_AGENT_QT_IMPORT_LIBRARIES "${_ida_qt_import}")
endforeach()
message(STATUS "Using Qt import libraries generated from: ${IDA_AGENT_IDA_QT_RUNTIME_DIR}")
