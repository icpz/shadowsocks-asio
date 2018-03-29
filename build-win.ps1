cmake -DVCPKG_TARGET_TRIPLET="${Env:VCPKG_DEFAULT_TRIPLET}" -DCMAKE_TOOLCHAIN_FILE="${Env:VCPKG_ROOT}\scripts\buildsystems\vcpkg.cmake" -DCMAKE_INSTALL_PREFIX="${Env:HOMEPATH}\Documents" -G "Visual Studio 15 2017 Win64"
cmake --build . --config Release

