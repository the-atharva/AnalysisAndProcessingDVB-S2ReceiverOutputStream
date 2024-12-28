#pragma once

#include <string>

class ProcessTS{
public:
    std::string pcap_file_location;
    std::string output_file_location;
    std::string intermediate_file_location;
    std::string file_name;

    ProcessTS(std::string pcap_file_location, std::string output_file_location,
        std::string intermediate_file_location, std::string file_name);
    bool convert_to_intermediate();
    bool convert_to_final();
    bool analyze_and_process();

};
