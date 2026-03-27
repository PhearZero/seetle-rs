cmake_minimum_required(VERSION 3.21.0)
project(tropic_seelte)

# Configure libtropic
set(LT_HELPERS ON CACHE BOOL "")
set(LT_SILICON_REV "ACAB" CACHE BOOL "")

# Add libtropic
add_subdirectory(../libtropic libtropic_sdk)

# HAL: Mock
add_subdirectory(../libtropic/hal/mock libtropic_mock_hal)
target_sources(tropic PRIVATE ${LT_HAL_SRCS})
target_include_directories(tropic PUBLIC ${LT_HAL_INC_DIRS})

# CAL: Trezor Crypto
add_subdirectory(../libtropic/cal/trezor_crypto libtropic_trezor_cal)
target_sources(tropic PRIVATE ${LT_CAL_SRCS})
target_include_directories(tropic PUBLIC ${LT_CAL_INC_DIRS})

# Vendor: Trezor Crypto
add_subdirectory(../libtropic/vendor/trezor_crypto libtropic_trezor_vendor)
target_link_libraries(tropic PRIVATE trezor_crypto)

# Export the library
add_library(tropic_seelte STATIC seelte_wrapper.c)
target_link_libraries(tropic_seelte PRIVATE tropic)
target_include_directories(tropic_seelte PRIVATE ../libtropic/include ../libtropic/hal/mock)

install(TARGETS tropic trezor_crypto tropic_seelte DESTINATION lib)
