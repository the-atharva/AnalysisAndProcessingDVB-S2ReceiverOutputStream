#include "ProcessGSE.h"

#include <SystemUtils.h>
#include <Packet.h>
#include <PcapFileDevice.h>
// #include <fmt/core.h>
// #include <fmt/color.h>

#include <string>
#include <fstream>
#include <cstdint>
#include <iostream>

ProcessGSE::ProcessGSE(std::string pcap_file_location, std::string output_file_location,
    std::string intermediate_file_location, std::string file_name)
    :pcap_file_location(pcap_file_location), output_file_location(output_file_location),
    intermediate_file_location(intermediate_file_location), file_name(file_name) {
        total_bytes = 0;
        total_packets = 0;
}

bool ProcessGSE::convert_to_intermediate(){
    pcpp::PcapFileReaderDevice reader(pcap_file_location);
    if(!reader.open()){
        std::cout << "Error opening pcap file: " << file_name << std::endl;
        return false;
    }
    std::ofstream intermediate_file (intermediate_file_location,
        std::ios::out | std::ios::binary | std::ios::trunc);
        if(!intermediate_file.is_open()){
            std::cout << "Error opening binary file" << std::endl;
            return false;
        }
        pcpp::RawPacket rawPacket;
        while(reader.getNextPacket(rawPacket)){
            pcpp::Packet packet(&rawPacket);
            pcpp::Layer *curr_layer = packet.getLastLayer();
            if(curr_layer->getProtocol() != pcpp::GenericPayload) continue;
            ++total_packets;
            size_t n = curr_layer->getDataLen();
            uint8_t *char_ptr = curr_layer->getData();
            total_bytes += n;
            while(n--){
                intermediate_file.write((char *)char_ptr, 1);
                char_ptr++;
            }
        }
        reader.close();
        intermediate_file.close();
        return true;
}

bool ProcessGSE::convert_to_final(){
    std::ifstream intermediate_file (intermediate_file_location, std::ios::in | std::ios::binary);
    if(!intermediate_file.is_open()){
        std::cout<< "Error opening binary file: " << file_name << std::endl;
        return false;
    }
    std::ofstream final_file (output_file_location, std::ios::out | std::ios::trunc);
    if(!final_file.is_open()){
        std::cout << "Error opening text file: " << file_name << std::endl;
        return false;
    }
    char byte;
    while(intermediate_file.get(byte)){
        final_file<<byte;
    }
    intermediate_file.close();
    final_file.close();
    return true;
}

bool ProcessGSE::analyze_and_process(){
    if(convert_to_intermediate()){
        return convert_to_final();
    }
    return false;
}
