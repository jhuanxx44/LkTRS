find_path(PBC_INCLUDE_DIR NAMES pbc/pbc.h)
find_library(PBC_LIBRARY NAMES pbc)
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARY NAMES gmp)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PBC REQUIRED_VARS
    PBC_INCLUDE_DIR PBC_LIBRARY GMP_INCLUDE_DIR GMP_LIBRARY)
if(PBC_FOUND AND NOT TARGET PBC::PBC)
    add_library(PBC::PBC INTERFACE IMPORTED)
    set_target_properties(PBC::PBC PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${PBC_INCLUDE_DIR};${GMP_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${PBC_LIBRARY};${GMP_LIBRARY}")
    if(UNIX)
        target_link_libraries(PBC::PBC INTERFACE m)
    endif()
endif()
mark_as_advanced(PBC_INCLUDE_DIR PBC_LIBRARY GMP_INCLUDE_DIR GMP_LIBRARY)
