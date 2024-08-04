file(GLOB HEADER_LIST CONFIGURE_DEPENDS "${rutoken-ecp-util_SOURCE_DIR}/src/*.h")

add_executable(rutoken-ecp-util rutoken-ecp-util.c ${HEADER_LIST})
add_library(rutoken-ecp-lib rutoken-ecp.c ${HEADER_LIST})

target_link_libraries(rutoken-ecp-util rutoken-ecp-lib dl)
