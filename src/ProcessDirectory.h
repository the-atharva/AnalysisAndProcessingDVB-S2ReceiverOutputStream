#pragma once

#include "Utils.h"

#include <filesystem>
#include <string>
#include <regex>

class ProcessDirectory {
public:
    std::filesystem::directory_entry input_directory;
    std::filesystem::directory_entry output_directory;
    int process_count;
    std::regex pcap_extension;

    ProcessDirectory();
    ProcessDirectory(std::filesystem::directory_entry input_directory,
    std::filesystem::directory_entry output_directory);
    find_protocols::payload_protocols get_payload_protocol(
        std::filesystem::directory_entry pcap_file_location,
        std::string file_name);
    std::string get_name(std::filesystem::directory_entry pcap_file_location);
    std::string get_intermediate_location(std::string file_name,
        find_protocols::payload_protocols payload_protocol);
    std::string get_output_location(std::string file_name,
        find_protocols::payload_protocols payload_protocol);
    bool analyze_and_process();
    bool prepare_directories();

};
