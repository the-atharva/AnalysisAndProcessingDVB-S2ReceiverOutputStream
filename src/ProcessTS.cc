#include "ProcessTS.h"

#include <SystemUtils.h>
#include <Packet.h>
#include <PcapFileDevice.h>

#include <string>
#include <fstream>
#include <cstdint>
#include <iostream>
#include <filesystem>

ProcessTS::ProcessTS(std::string pcap_file_location, std::string output_file_location,
    std::string intermediate_file_location, std::string file_name)
    :pcap_file_location(pcap_file_location), output_file_location(output_file_location),
    intermediate_file_location(intermediate_file_location), file_name(file_name) {
}

bool ProcessTS::convert_to_intermediate(){
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
            size_t n = curr_layer->getDataLen();
            uint8_t *char_ptr = curr_layer->getData();

            while(n--){
                intermediate_file.write((char *)char_ptr, 1);
                char_ptr++;
            }
    }
    reader.close();
    intermediate_file.close();
    return true;
}

bool ProcessTS::convert_to_final(){
    std::filesystem::remove(output_file_location);
    std::string command = std::string("ffmpeg -i ") +
        intermediate_file_location + std::string(" ") + output_file_location;
    system(command.c_str());
    system("clear");
    return true;
// ffmpeg -i output_ts_file.ts output_video_file.mp4
}

bool ProcessTS::analyze_and_process(){
    if(convert_to_intermediate()){
        return convert_to_final();
    }
    return false;
}
