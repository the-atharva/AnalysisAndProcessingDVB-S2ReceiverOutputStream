#pragma once

#include <string>

class ProcessGSE{
public:
    std::string pcap_file_location;
    std::string output_file_location;
    std::string intermediate_file_location;
    std::string file_name;
    int total_bytes;
    int total_packets;

    ProcessGSE(std::string pcap_file_location, std::string output_file_location,
        std::string intermediate_file_location, std::string file_name);
    bool convert_to_intermediate();
    bool convert_to_final();
    bool analyze_and_process();

};
