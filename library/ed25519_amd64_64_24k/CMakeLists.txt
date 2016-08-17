# Just define x25519 implementation source files

file(GLOB src_c "*.c")
file(GLOB src_s "*.s")
set(src_x25519 "${src_c}" "${src_s}" CACHE INTERNAL "")
