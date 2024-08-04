cmake_minimum_required(VERSION 3.28.3)
project(rutoken-ecp-util VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include(CTest)
include(FetchContent)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(src)
add_subdirectory(tests)
