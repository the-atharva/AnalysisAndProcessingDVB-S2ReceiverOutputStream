# Utils Library
set(UTIL_LIBRARY_NAME UTIL_LIBRARY)
set(UTIL_LIBRARY_SOURCES "${PROJECT_SOURCE_DIR}/src/Utils.cc")
set(UTIL_LIBRARY_HEADERS "${PROJECT_SOURCE_DIR}/src/Utils.h")
add_library(${UTIL_LIBRARY_NAME} SHARED
            ${UTIL_LIBRARY_SOURCES}
            ${UTIL_LIBRARY_HEADERS}
)
target_link_libraries(${UTIL_LIBRARY_NAME}
                    PRIVATE
                    PcapPlusPlus::Pcap++
)

#Process GSE
add_library(PROCESS_GSE SHARED
            "${PROJECT_SOURCE_DIR}/src/ProcessGSE.cc"
            "${PROJECT_SOURCE_DIR}/src/ProcessGSE.h")
target_link_libraries(PROCESS_GSE
                    PRIVATE
                    PcapPlusPlus::Pcap++
                    # fmt::fmt
                    ${UTIL_LIBRARY_NAME})

#Process TS
add_library(PROCESS_TS SHARED
            "${PROJECT_SOURCE_DIR}/src/ProcessTS.cc"
            "${PROJECT_SOURCE_DIR}/src/ProcessTS.h")
target_link_libraries(PROCESS_TS
                    PRIVATE
                    PcapPlusPlus::Pcap++
                    ${UTILS_LIBRARY_NAME})

#Process Direcetory
add_library(PROCESS_DIRECTORY STATIC
            "${PROJECT_SOURCE_DIR}/src/ProcessDirectory.cc"
            "${PROJECT_SOURCE_DIR}/src/ProcessDirectory.h")
target_link_libraries(PROCESS_DIRECTORY
                    PRIVATE
                    PcapPlusPlus::Pcap++
                    fmt::fmt
                    ${UTILS_LIBRARY_NAME}
                    PROCESS_GSE
                    PROCESS_TS
)

# target_include_directories(${LIBRARY_NAME} PUBLIC
#     "./"
#     "${CMAKE_BINARY_DIR}/configured_files/include"
# )
target_set_warnings(PROCESS_DIRECTORY)
target_set_warnings(PROCESS_GSE)
target_set_warnings(PROCESS_TS)
# target_set_warnings(PROCESS_DIRECTORY)
