#pragma once

// A static archive contributes only the objects a link needs, so a binary that
// reaches both library variants would take each object from whichever archive
// resolves it first, and CMake's variant check cannot see a variant hidden behind
// a consumer's PRIVATE static link. Every object therefore references its variant's
// marker, both markers live in objects that also define the shared
// vnm_filesystem_observation_variant_guard, and an object from each variant makes
// the link fail with a duplicate definition of it.
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
#define VNM_FILESYSTEM_OBSERVATION_VARIANT_MARKER vnm_filesystem_observation_test_hooks_variant
#else
#define VNM_FILESYSTEM_OBSERVATION_VARIANT_MARKER vnm_filesystem_observation_product_variant
#endif

extern "C" const char VNM_FILESYSTEM_OBSERVATION_VARIANT_MARKER;

// The reference has external linkage so that no compiler drops it, and with it the
// undefined symbol that pulls in the marker's object.
#define VNM_FILESYSTEM_OBSERVATION_REFERENCE_VARIANT(unit) \
    extern "C" const char* const vnm_filesystem_observation_##unit##_variant_reference; \
    extern "C" const char* const vnm_filesystem_observation_##unit##_variant_reference = \
        &VNM_FILESYSTEM_OBSERVATION_VARIANT_MARKER;
