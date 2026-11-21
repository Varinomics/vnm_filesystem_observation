cmake_minimum_required(VERSION 3.21)

if(TARGET vnm_framework::vnm_filesystem_observation)
    return()
endif()

find_package(Qt6 6.12 REQUIRED COMPONENTS Core)
find_package(Threads REQUIRED)
if(NOT TARGET vnm_qt_dispatch::vnm_qt_dispatch AND
   NOT VNM_QT_DISPATCH_SOURCE_DIR AND
   NOT FETCHCONTENT_SOURCE_DIR_VNM_QT_DISPATCH)
    find_package(vnm_qt_dispatch 2 CONFIG QUIET)
endif()
if(NOT TARGET vnm_qt_dispatch::vnm_qt_dispatch)
    include("${CMAKE_CURRENT_LIST_DIR}/../cmake/vnm_cmake_dependency.cmake")
    if(VNM_QT_DISPATCH_SOURCE_DIR)
        set(FETCHCONTENT_SOURCE_DIR_VNM_QT_DISPATCH "${VNM_QT_DISPATCH_SOURCE_DIR}")
    endif()
    vnm_acquire_owned_dependency(NAME vnm_qt_dispatch
        GIT_REPOSITORY "https://github.com/Varinomics/vnm_qt_dispatch.git"
        SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/.."
        TARGET vnm_qt_dispatch::vnm_qt_dispatch)
endif()

set(_vnm_observation_test_default OFF)
if(BUILD_TESTING AND PROJECT_IS_TOP_LEVEL)
    set(_vnm_observation_test_default ON)
endif()
option(VNM_FILESYSTEM_OBSERVATION_BUILD_TESTS
    "Build filesystem observation tests" ${_vnm_observation_test_default})
option(VNM_FILESYSTEM_OBSERVATION_ENABLE_TEST_HOOKS
    "Also build vnm_filesystem_observation_test_hooks, the fault-injection variant"
    ${VNM_FILESYSTEM_OBSERVATION_BUILD_TESTS})
if(VNM_FILESYSTEM_OBSERVATION_BUILD_TESTS AND
   NOT VNM_FILESYSTEM_OBSERVATION_ENABLE_TEST_HOOKS)
    message(FATAL_ERROR
        "VNM_FILESYSTEM_OBSERVATION_BUILD_TESTS requires "
        "VNM_FILESYSTEM_OBSERVATION_ENABLE_TEST_HOOKS: "
        "the tests drive the fault-injection hooks.")
endif()

# Test hooks are fault-injection branches, so they must not reach a product binary.
# vnm_filesystem_observation never has them and is the only installed variant. With
# VNM_FILESYSTEM_OBSERVATION_ENABLE_TEST_HOOKS, the same sources also build
# vnm_filesystem_observation_test_hooks, which publishes the
# VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS definition to its consumers.
#
# Consumer contract: product targets link vnm_framework::vnm_filesystem_observation.
# A test that calls a *_for_tests entry point links
# vnm_framework::vnm_filesystem_observation_test_hooks instead, and so does every
# library of the consumer's that such a test links and that itself links this
# component. One binary never takes objects from both: they define the same
# symbols, and a linker would take each object from whichever archive resolves it
# first. Two checks enforce this. The VNM_FILESYSTEM_OBSERVATION_VARIANT compatible
# interface property makes CMake reject a target that links both variants directly
# or through PUBLIC and INTERFACE dependencies; it cannot see one behind a
# consumer's PRIVATE static link. The variant markers in
# vnm_filesystem_observation_variant.h cover that case at link time: objects from
# both archives make the link fail with a duplicate definition. Both archives on
# one link line are accepted when every object comes from one of them.
function(vnm_filesystem_observation_add_variant target variant)
    add_library(${target} STATIC
        vnm_filesystem_observation.cpp
        vnm_filesystem_observation.h
        vnm_filesystem_observation_qt.cpp
        vnm_filesystem_observation_qt.h
        vnm_filesystem_native_watcher.cpp
        vnm_filesystem_native_watcher.h
        vnm_direct_registry.cpp
        vnm_direct_registry_p.h
        vnm_directory_scan_p.cpp
        vnm_directory_scan_p.h
        vnm_direct_native_backend_p.h
        vnm_direct_native_drain_p.cpp
        vnm_direct_native_drain_p.h
        vnm_native_event_decode_p.cpp
        vnm_native_event_decode_p.h
        vnm_filesystem_native_event.h
        vnm_path_name.cpp
        vnm_path_name.h
        vnm_filesystem_observation_variant.cpp
        vnm_filesystem_observation_variant.h)
    add_library(vnm_framework::${target} ALIAS ${target})
    if(WIN32)
        # Expose the SDK's extended notification types; runtime resolution keeps
        # the API optional on the OS and each filesystem.
        set_source_files_properties(vnm_direct_native_backend_win.cpp
            vnm_native_event_decode_p.cpp tests/vnm_filesystem_native_watcher_tests.cpp
            PROPERTIES COMPILE_DEFINITIONS NTDDI_VERSION=0x0A000004)
        target_sources(${target} PRIVATE vnm_direct_native_backend_win.cpp vnm_windows_directory_identity_p.cpp)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR ANDROID)
        target_sources(${target} PRIVATE vnm_direct_native_backend_linux.cpp)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_sources(${target} PRIVATE vnm_direct_native_backend_mac.cpp)
        target_link_libraries(${target} PRIVATE "-framework CoreServices")
    endif()
    set_target_properties(${target} PROPERTIES
        AUTOMOC OFF AUTOUIC OFF AUTORCC OFF POSITION_INDEPENDENT_CODE ON
        INTERFACE_VNM_FILESYSTEM_OBSERVATION_VARIANT ${variant})
    set_property(TARGET ${target} APPEND PROPERTY
        COMPATIBLE_INTERFACE_STRING VNM_FILESYSTEM_OBSERVATION_VARIANT)
    target_compile_features(${target} PUBLIC cxx_std_20)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
        $<INSTALL_INTERFACE:include/vnm_framework/filesystem_observation>
        $<INSTALL_INTERFACE:include/vnm_framework>)
    target_link_libraries(${target}
        PUBLIC Qt6::Core
        PRIVATE vnm_qt_dispatch::vnm_qt_dispatch Threads::Threads)
    if(WIN32)
        target_compile_definitions(${target} PRIVATE
            NOMINMAX _WIN32_WINNT=0x0A00 WINVER=0x0A00)
    endif()
endfunction()

vnm_filesystem_observation_add_variant(vnm_filesystem_observation product)
if(VNM_FILESYSTEM_OBSERVATION_ENABLE_TEST_HOOKS)
    vnm_filesystem_observation_add_variant(vnm_filesystem_observation_test_hooks test_hooks)
    target_compile_definitions(vnm_filesystem_observation_test_hooks PUBLIC
        VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS)
endif()

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
install(TARGETS vnm_filesystem_observation EXPORT vnm_filesystem_observation_targets
    ARCHIVE DESTINATION lib)
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/../LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/../notices/vnm_qt_dispatch-BSD-2-Clause.txt"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/vnm_filesystem_observation")
install(FILES
    vnm_filesystem_observation.h
    vnm_filesystem_observation_qt.h
    vnm_filesystem_native_watcher.h
    vnm_filesystem_native_event.h
    vnm_path_name.h
    DESTINATION include/vnm_framework/filesystem_observation)
install(EXPORT vnm_filesystem_observation_targets
    NAMESPACE vnm_framework:: DESTINATION lib/cmake/vnm_filesystem_observation)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/vnm_filesystem_observation-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/vnm_filesystem_observation-config.cmake"
    INSTALL_DESTINATION lib/cmake/vnm_filesystem_observation)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/vnm_filesystem_observation-config-version.cmake"
    VERSION 1.0.0 COMPATIBILITY SameMajorVersion)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/vnm_filesystem_observation-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/vnm_filesystem_observation-config-version.cmake"
    DESTINATION lib/cmake/vnm_filesystem_observation)

if(VNM_FILESYSTEM_OBSERVATION_BUILD_TESTS)
    enable_testing()
    find_package(Qt6 6.12 REQUIRED COMPONENTS Test)
    foreach(test_name IN ITEMS filesystem_observation_scheduler_tests vnm_filesystem_native_watcher_tests)
        add_executable(${test_name} tests/${test_name}.cpp)
        set_target_properties(${test_name} PROPERTIES AUTOMOC ON)
        target_link_libraries(${test_name} PRIVATE
            vnm_framework::vnm_filesystem_observation_test_hooks Qt6::Test)
        if(COMMAND vnm_add_diagnostic_test)
            vnm_add_diagnostic_test(NAME ${test_name} TIMEOUT 120 COMMAND $<TARGET_FILE:${test_name}>)
            vnm_set_test_environment(${test_name})
        else()
            add_test(NAME ${test_name} COMMAND ${test_name})
            set_tests_properties(${test_name} PROPERTIES TIMEOUT 120 ENVIRONMENT "QT_FORCE_STDERR_LOGGING=1")
            if(WIN32)
                string(REPLACE ";" "\\;" test_path "$ENV{PATH}")
                set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT
                    "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;${test_path}")
            endif()
        endif()
    endforeach()
endif()
