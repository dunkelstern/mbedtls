# Just define x25519 implementation source files

file(GLOB src "ed25519_impl/*.c")

set(src_x25519 "${src}" CACHE INTERNAL "")
