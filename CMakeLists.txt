cmake_minimum_required(VERSION 3.22)
PROJECT(
    DVBS2ReceiverOutputAnalysis&Processing
    VERSION 1.0.0
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(EXECUTABLE_NAME Executable)

find_package(PcapPlusPlus REQUIRED)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(Warnings)
include(Sanitizers)
include(CPM)
# cpmaddpackage("gh:nlohmann/json#v3.11.3")
cpmaddpackage("gh:fmtlib/fmt#11.0.2")
# cpmaddpackage("gh:gabime/spdlog#v1.14.1")
cpmaddpackage("gh:jarro2783/cxxopts#v3.2.0")
# cpmaddpackage("gh:catchorg/Catch2#v3.7.1")
# list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
add_sanitizer_flags()
add_subdirectory(configured)
add_subdirectory(src)
add_subdirectory(app)
