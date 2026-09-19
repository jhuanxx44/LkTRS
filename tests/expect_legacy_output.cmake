# Regression check for the documented legacy baseline (design doc W01).
#
# The unfinished demo must keep reaching KeyGen and must keep refusing to
# verify. A "verify OK"/"verify succeeded" line, or a nonzero exit, fails this
# test. This only asserts that the known-broken behaviour is stable; it is not
# evidence that any signature scheme works.
#
# Required variables:
#   LEGACY_EXECUTABLE  path to the built legacy demo
#   REQUIRED_TEXT      text the demo must print (default: "verify failed")

if(NOT DEFINED LEGACY_EXECUTABLE OR NOT EXISTS "${LEGACY_EXECUTABLE}")
    message(FATAL_ERROR "LEGACY_EXECUTABLE is missing or does not exist: '${LEGACY_EXECUTABLE}'")
endif()
if(NOT DEFINED REQUIRED_TEXT OR REQUIRED_TEXT STREQUAL "")
    set(REQUIRED_TEXT "verify failed")
endif()

execute_process(
    COMMAND "${LEGACY_EXECUTABLE}"
    RESULT_VARIABLE legacy_exit
    OUTPUT_VARIABLE legacy_stdout
    ERROR_VARIABLE legacy_stderr
    TIMEOUT 60)

if(NOT legacy_exit EQUAL 0)
    message(FATAL_ERROR
        "legacy demo exited with ${legacy_exit}; main() must return 0.\n"
        "stdout:\n${legacy_stdout}\nstderr:\n${legacy_stderr}")
endif()

# main() must still reach the KeyGen path. Asserting this alongside the failure
# text distinguishes "rejected the proof" from "died or printed nothing".
if(NOT legacy_stdout MATCHES "Key generation successful")
    message(FATAL_ERROR
        "legacy demo did not reach KeyGen; baseline moved.\nstdout:\n${legacy_stdout}")
endif()

if(NOT legacy_stdout MATCHES "${REQUIRED_TEXT}")
    message(FATAL_ERROR
        "legacy demo did not print '${REQUIRED_TEXT}'; verification may have started succeeding.\n"
        "stdout:\n${legacy_stdout}")
endif()

# Guard against a future stub that prints both outcomes.
if(legacy_stdout MATCHES "verify OK" OR legacy_stdout MATCHES "verify succeeded")
    message(FATAL_ERROR
        "legacy demo reported a successful verification; the fail-closed contract is broken.\n"
        "stdout:\n${legacy_stdout}")
endif()

message(STATUS "legacy demo reaches KeyGen and still fails closed")
