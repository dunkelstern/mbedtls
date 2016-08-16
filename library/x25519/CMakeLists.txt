# Just define x25519 implementation source files

file(GLOB src "ed25519_impl/*.c")

set(src_x25519 "${CMAKE_CURRENT_SOURCE_DIR}/x25519.c" "${src}" CACHE INTERNAL "")
