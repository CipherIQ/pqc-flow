cmake_minimum_required(VERSION 3.16)
project(pqc_flow_starter C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Options
option(ENABLE_TESTS "Build unit tests" ON)

# Find libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Find OpenSSL (for SHA256 fingerprinting and X509 parsing)
find_package(OpenSSL REQUIRED)

# Find nDPI (expects pkg-config file 'ndpi' on your system)
# On some systems it's named 'ndpi' or 'libndpi'. Try both.
pkg_check_modules(NDPI QUIET ndpi)
if(NOT NDPI_FOUND)
  pkg_check_modules(NDPI REQUIRED libndpi)
endif()

include_directories(
  ${NDPI_INCLUDE_DIRS}
  ${PCAP_INCLUDE_DIRS}
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

link_directories(
  ${NDPI_LIBRARY_DIRS}
  ${PCAP_LIBRARY_DIRS}
)

add_compile_options(${NDPI_CFLAGS_OTHER} ${PCAP_CFLAGS_OTHER})
add_executable(pqc-flow
  src/main.c
  src/flow.c
  src/pqc_detect.c
  src/ndpi_glue.c
  src/run_afpacket.c
  src/pcap_offline.c
  src/ssh_kex_sniffer.c
  src/tls_pqc_sniffer.c
)

target_link_libraries(pqc-flow
  ${NDPI_LIBRARIES}
  ${PCAP_LIBRARIES}
  OpenSSL::SSL
  OpenSSL::Crypto
)

# Tests (simple C unit tests without external frameworks)
if(ENABLE_TESTS)
  add_executable(pqc-tests
    tests/test_pqc.c
    src/pqc_detect.c
    src/flow.c
  )
  target_include_directories(pqc-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_link_libraries(pqc-tests ${NDPI_LIBRARIES})
endif()
