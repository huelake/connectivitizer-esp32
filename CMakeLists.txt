# The library as an ESP-IDF component: put this folder into your project's "components" folder.
idf_component_register(
    SRC_DIRS "src" "src/port" "src/vendor"
    INCLUDE_DIRS "src"
    PRIV_REQUIRES esp-tls esp_netif lwip
)
# The vendored sources are compiled as their authors publish them; their warnings are not ours to fix.
set_source_files_properties(src/vendor/monocypher.c src/vendor/uECC.c src/vendor/ikcp.c PROPERTIES COMPILE_OPTIONS "-w")
