# Filesystem observation

The observation service watches paths and directories on Windows, Linux and macOS.
It provides native events, ordered observations, and delivery to a Qt object.
The public headers live under `filesystem_observation/`.

Use CMake 3.21 or newer, a C++20 compiler and Qt 6.12 Core. The standalone tests
also use Qt Test. With the Qt installation in `CMAKE_PREFIX_PATH`, build and run
the tests from the repository root.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Source consumers use `add_subdirectory()` on this checkout. Installed consumers
use `find_package(vnm_filesystem_observation CONFIG REQUIRED)`. Both link
`vnm_framework::vnm_filesystem_observation`. The build also accepts an installed
`vnm_qt_dispatch` 2 package or its source checkout.

The implementation and tests originate in Varinomics’ `vnm_framework`.
