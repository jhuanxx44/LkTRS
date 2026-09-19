cmake_minimum_required(VERSION 3.18)
project(LkTRS VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_EXTENSIONS OFF)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(LKTRS_BUILD_LEGACY "Build the incomplete, unsafe legacy demo (not a valid signature scheme)" OFF)
option(LKTRS_WARNINGS_AS_ERRORS "Treat warnings in new project code as errors" ON)
option(LKTRS_NATIVE_PROOF "Build connected Go/gnark backend and slow C++ proof test" OFF)
option(LKTRS_SANITIZERS "Instrument project code with AddressSanitizer and UBSan" OFF)

find_package(PBC REQUIRED)
find_path(LKTRS_SODIUM_INCLUDE_DIR NAMES sodium.h)
find_library(LKTRS_SODIUM_LIBRARY NAMES sodium libsodium)
if(NOT LKTRS_SODIUM_INCLUDE_DIR OR NOT LKTRS_SODIUM_LIBRARY)
    message(FATAL_ERROR
        "libsodium is required for the standalone DDH G_p backend "
        "(install libsodium development headers and library)")
endif()
add_library(lktrs_build_options INTERFACE)
target_compile_features(lktrs_build_options INTERFACE cxx_std_17)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(lktrs_build_options INTERFACE -Wall -Wextra -Wpedantic)
endif()
if(LKTRS_SANITIZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "LKTRS_SANITIZERS requires GCC or Clang")
    endif()
    target_compile_options(lktrs_build_options INTERFACE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(lktrs_build_options INTERFACE -fsanitize=address,undefined)
endif()

function(lktrs_strict target)
    if(LKTRS_WARNINGS_AS_ERRORS AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -Werror)
    endif()
endfunction()

add_library(lktrs_crypto STATIC
    src/crypto/pairing.cpp
    src/crypto/sha256.cpp
    src/crypto/ddh.cpp
    src/protocol/accumulator.cpp
    src/protocol/clear.cpp
    src/protocol/serialization.cpp
    src/protocol/native_process.cpp)

add_library(LkTRS::crypto ALIAS lktrs_crypto)
target_include_directories(lktrs_crypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(lktrs_crypto PRIVATE "${LKTRS_SODIUM_INCLUDE_DIR}")
target_link_libraries(lktrs_crypto PUBLIC PBC::PBC "${LKTRS_SODIUM_LIBRARY}" lktrs_build_options)
lktrs_strict(lktrs_crypto)

find_package(Threads REQUIRED)
target_link_libraries(lktrs_crypto PUBLIC Threads::Threads)

include(CTest)

# The original protocol source files live under src/legacy and are intentionally
# isolated from the resource library. The connected native proof profile is separate;
# building the demo does not make it a working Lk-TRS. Tests build it so the
# fail-closed contract can be regressed instead of only documented.
# This must come after include(CTest): otherwise BUILD_TESTING is undefined here.
if(LKTRS_BUILD_LEGACY OR BUILD_TESTING)
    message(WARNING "Building legacy prototype: verification is unavailable; do not use real secrets")
    add_executable(lktrs
        src/legacy/spk.cpp
        src/legacy/lktrs.cpp
        src/legacy/accumulator.cpp
        src/legacy/main.cpp)
    target_include_directories(lktrs PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/legacy")
    target_link_libraries(lktrs PRIVATE PBC::PBC lktrs_build_options)
    # The unchanged legacy SPK file has a known unused-parameter warning. It is
    # not migrated code, so it is not held to the new-code -Werror policy.
endif()

if(BUILD_TESTING)
    add_executable(native_process_tests tests/native_process_tests.cpp)
    target_link_libraries(native_process_tests PRIVATE LkTRS::crypto)
    lktrs_strict(native_process_tests)
    add_test(NAME native_process COMMAND native_process_tests)
    set_tests_properties(native_process PROPERTIES TIMEOUT 120)

    add_executable(ddh_resource_tests tests/ddh_resource_tests.cpp)
    target_link_libraries(ddh_resource_tests PRIVATE LkTRS::crypto)
    lktrs_strict(ddh_resource_tests)
    add_test(NAME ddh_resource COMMAND ddh_resource_tests)
    set_tests_properties(ddh_resource PROPERTIES TIMEOUT 120)

    add_executable(crypto_resource_tests tests/crypto_resource_tests.cpp)
    target_link_libraries(crypto_resource_tests PRIVATE LkTRS::crypto)
    lktrs_strict(crypto_resource_tests)
    foreach(fixture IN ITEMS type-a-legacy type-f-pbc)
        add_test(NAME crypto_${fixture} COMMAND crypto_resource_tests
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/${fixture}.param")
        set_tests_properties(crypto_${fixture} PROPERTIES TIMEOUT 120)
    endforeach()
    add_test(NAME crypto_composite_order_rejected COMMAND crypto_resource_tests
        --reject-composite "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/type-a1-rejected.param")
    set_tests_properties(crypto_composite_order_rejected PROPERTIES TIMEOUT 120)

    add_executable(accumulator_tests tests/accumulator_tests.cpp)
    target_link_libraries(accumulator_tests PRIVATE LkTRS::crypto)
    lktrs_strict(accumulator_tests)
    foreach(fixture IN ITEMS type-a-legacy type-f-pbc)
        add_test(NAME accumulator_${fixture} COMMAND accumulator_tests
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/${fixture}.param")
        set_tests_properties(accumulator_${fixture} PROPERTIES TIMEOUT 120)
    endforeach()

    add_executable(clear_protocol_tests tests/clear_protocol_tests.cpp)
    target_link_libraries(clear_protocol_tests PRIVATE LkTRS::crypto)
    lktrs_strict(clear_protocol_tests)
    add_test(NAME clear_protocol COMMAND clear_protocol_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/type-a-legacy.param")
    set_tests_properties(clear_protocol PROPERTIES TIMEOUT 120)

    add_executable(serialization_tests tests/serialization_tests.cpp)
    target_link_libraries(serialization_tests PRIVATE LkTRS::crypto)
    lktrs_strict(serialization_tests)
    add_test(NAME serialization COMMAND serialization_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/type-a-legacy.param")
    set_tests_properties(serialization PROPERTIES TIMEOUT 120)

    # Test only the old verifier's fail-closed contract, without running the
    # legacy sign/keygen/trace paths or pretending that an SPK exists.
    add_executable(legacy_fail_closed tests/legacy_fail_closed.cpp src/legacy/spk.cpp)
    target_include_directories(legacy_fail_closed PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/legacy")
    target_link_libraries(legacy_fail_closed PRIVATE PBC::PBC lktrs_build_options)
    add_test(NAME legacy_fail_closed COMMAND legacy_fail_closed)
    set_tests_properties(legacy_fail_closed PROPERTIES
        LABELS "legacy;known-leaks")

    # Regression for the documented W01 baseline: the legacy demo must keep
    # reaching KeyGen and must keep refusing every proof. This asserts the
    # observed failure is stable; it is not a test of any scheme behaviour.
    #
    # This test deliberately executes a leaking code path: LkTRS::KeyGen
    # allocates G1 elements (src/legacy/lktrs.cpp) and never clears them. That is
    # the frozen W01 baseline, and AGENTS.md rule 3 forbids fixing legacy in
    # place without an ADR, so the leak is recorded rather than repaired.
    #
    # Linux CI sets ASAN_OPTIONS=detect_leaks=1:halt_on_error=1, so this known
    # leak aborts the child and the test would fail on a fact already documented.
    # The test therefore carries the "known-leaks" label, and the Linux
    # leak-detection invocation excludes only that label (`ctest -LE known-leaks`);
    # the leak-detected run still covers every other test, and a separate
    # `ctest -L known-leaks` run keeps these baselines visible without asking leak
    # detection to bless them. Leak checking is NOT globally disabled.
    add_test(NAME legacy_demo_fails_closed
        COMMAND "${CMAKE_COMMAND}"
            -DREQUIRED_TEXT=verify failed
            -DLEGACY_EXECUTABLE=$<TARGET_FILE:lktrs>
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/expect_legacy_output.cmake")
    set_tests_properties(legacy_demo_fails_closed PROPERTIES
        TIMEOUT 120
        LABELS "legacy;known-leaks;demo")

    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME known_broken_models COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/known_broken_models.py")
    set_tests_properties(known_broken_models PROPERTIES LABELS "negative-model;not-protocol-validation")
endif()

# Native-profile code is Go because gnark provides the actual Groth16 backend.
# It is versioned separately from the PBC clear reference; no point/scalar
# encoding is silently converted between the two profiles.
if(LKTRS_NATIVE_PROOF)
    find_program(LKTRS_GO_EXECUTABLE NAMES go REQUIRED)
    file(GLOB_RECURSE LKTRS_GO_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/nativeproof/*.go")
    set(LKTRS_NATIVE_EXECUTABLE "${CMAKE_CURRENT_BINARY_DIR}/lktrs-native")
    add_custom_command(OUTPUT "${LKTRS_NATIVE_EXECUTABLE}"
        COMMAND "${LKTRS_GO_EXECUTABLE}" build -mod=readonly -o "${LKTRS_NATIVE_EXECUTABLE}" ./cmd/lktrs-native
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src/nativeproof"
        DEPENDS ${LKTRS_GO_SOURCES} src/nativeproof/go.mod src/nativeproof/go.sum
        VERBATIM)
    add_custom_target(lktrs_native_backend ALL DEPENDS "${LKTRS_NATIVE_EXECUTABLE}")
    if(BUILD_TESTING)
        add_executable(native_backend_tests tests/native_backend_tests.cpp)
        target_link_libraries(native_backend_tests PRIVATE LkTRS::crypto)
        lktrs_strict(native_backend_tests)
        add_dependencies(native_backend_tests lktrs_native_backend)
        add_test(NAME native_groth16_end_to_end COMMAND native_backend_tests "${LKTRS_NATIVE_EXECUTABLE}")
        set_tests_properties(native_groth16_end_to_end PROPERTIES TIMEOUT 1200 LABELS "native;groth16;slow")
    endif()
endif()
