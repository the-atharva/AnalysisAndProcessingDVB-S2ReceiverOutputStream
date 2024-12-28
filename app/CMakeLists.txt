add_executable(${EXECUTABLE_NAME} main.cc)
target_link_libraries(${EXECUTABLE_NAME}
                    PUBLIC
                    cxxopts::cxxopts
                    fmt::fmt
                    PcapPlusPlus::Pcap++
                    PROCESS_DIRECTORY
)
target_include_directories(${EXECUTABLE_NAME} PUBLIC
                            "${PROJECT_SOURCE_DIR}/src")
target_set_warnings(${EXECUTABLE_NAME})
