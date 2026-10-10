include(FetchContent)
FetchContent_Declare(ida_sqlite
    URL https://sqlite.org/2026/sqlite-amalgamation-3530400.zip
    URL_HASH SHA256=1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d
    TLS_VERIFY TRUE
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(ida_sqlite)
add_library(ida_sqlite STATIC "${ida_sqlite_SOURCE_DIR}/sqlite3.c")
set_target_properties(ida_sqlite PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
target_include_directories(ida_sqlite SYSTEM PUBLIC "${ida_sqlite_SOURCE_DIR}")
target_compile_definitions(ida_sqlite PRIVATE SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION
    SQLITE_DEFAULT_MEMSTATUS=0)
target_link_libraries(ida_sqlite PUBLIC Threads::Threads m)
if(NOT APPLE)
    target_link_options(ida_sqlite INTERFACE "LINKER:--exclude-libs,libida_sqlite.a")
endif()
