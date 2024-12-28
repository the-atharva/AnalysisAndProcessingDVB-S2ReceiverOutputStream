#include "Utils.h"
#include "ProcessDirectory.h"
#include "ProcessGSE.h"
#include "ProcessTS.h"

#include <SystemUtils.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <fmt/core.h>
#include <fmt/color.h>

#include <filesystem>
#include <iostream>
#include <string>

ProcessDirectory::ProcessDirectory(){}

ProcessDirectory::ProcessDirectory(std::filesystem::directory_entry input_directory,
    std::filesystem::directory_entry output_directory) : input_directory(input_directory),
    output_directory(output_directory){
    process_count = 0;
    pcap_extension = std::regex(".*\\.pcap");
}

find_protocols::payload_protocols ProcessDirectory::get_payload_protocol(
    std::filesystem::directory_entry pcap_file_location,
    std::string file_name){
    pcpp::PcapFileReaderDevice reader(pcap_file_location.path().string());
    if(!reader.open()){
        std::cout << "Error opening pcap file: " << file_name <<std::endl;
        return find_protocols::payload_protocols::UD;
    }
    bool is_ts = true, is_gse;
    pcpp::RawPacket raw_packet;
    // improve logic very fragile code
    while(reader.getNextPacket(raw_packet)){
        pcpp::Packet packet(&raw_packet);
        pcpp::Layer *curr_layer = packet.getLayerOfType(pcpp::GenericPayload);
        if(curr_layer == nullptr){
            return find_protocols::payload_protocols::GSE;
        }
        return find_protocols::payload_protocols::TS;
    //     curr_layer = packet.getLayerOfType(pcpp::UDP);
    //     if(curr_layer == nullptr){
    //         return determine_protocols::payload_protocols::UD;
    //     }
    //     // if(curr_layer->getProtocol() != pcpp::GenericPayload) continue;
    //     uint8_t *data_ptr = curr_layer->getData();
    //     // std::cout << char(*data_ptr) << " ";
    //     // if(*data_ptr != 71) is_ts = false;
    //     if(*data_ptr != 184) is_ts = false;
    }
    // reader.close();
    // if(is_ts) return determine_protocols::payload_protocols::TS;
    // else return determine_protocols::payload_protocols::GSE;
}

std::string ProcessDirectory::get_name(std::filesystem::directory_entry pcap_file_location){
    return pcap_file_location.path().stem().string();
}

std::string ProcessDirectory::get_intermediate_location(std::string file_name,
    find_protocols::payload_protocols payload_protocol){
    std::string intermediate_file_location = output_directory.path().string() +
        std::string("/") + directory_types::intermediate +
        std::string("/") + file_name + std::string(".") +
        protocol_extensions::payload_intermediate_extensions
        .at(payload_protocol);
    return intermediate_file_location;
}

std::string ProcessDirectory::get_output_location(std::string file_name,
    find_protocols::payload_protocols payload_protocol){
    std::string output_file_location = output_directory.path().string() +
        std::string("/") + directory_types::output +
        std::string("/") +
        protocol_directories::payload_output_directory.at(payload_protocol) +
        std::string("/") + file_name + std::string(".") +
        protocol_extensions::payload_output_extensions.at(payload_protocol);
    return output_file_location;
}

bool ProcessDirectory::analyze_and_process(){
    for(const std::filesystem::directory_entry &pcap_file :
        std::filesystem::directory_iterator(input_directory)){
        if(!std::regex_match(pcap_file.path().string(), pcap_extension)) continue;
        std::string file_name = get_name(pcap_file);
        find_protocols::payload_protocols payload_protocol =
            get_payload_protocol(pcap_file, file_name);
        std::string intermediate_location =
            get_intermediate_location(file_name, payload_protocol);
        std::string output_file_location =
            get_output_location(file_name, payload_protocol);
        // std::cout << file_name << "\n" << intermediate_location <<
        //     "\n" << output_file_location << "\n\n\n";
        if(payload_protocol == find_protocols::payload_protocols::GSE) {
            ProcessGSE PGSE (pcap_file.path().string(), output_file_location,
                intermediate_location, file_name);
            PGSE.analyze_and_process();
        } else if (payload_protocol == find_protocols::payload_protocols::TS) {
            ProcessTS PTS (pcap_file.path().string(), output_file_location,
                intermediate_location, file_name);
            PTS.analyze_and_process();
        }
        ++process_count;
    }
    fmt::print(fg(fmt::color::lime_green), "Total files processed: {:5}\n", process_count);
    return true;
}

bool ProcessDirectory::prepare_directories(){
    std::filesystem::path intermediate_directory = output_directory.path().string() +
        std::string("/") + directory_types::intermediate;
    if(!std::filesystem::exists(intermediate_directory)){
        std::filesystem::create_directory(intermediate_directory);
    }
    std::filesystem::path final_output_directory = output_directory.path().string() +
        std::string("/") + directory_types::output;
    if(!std::filesystem::exists(final_output_directory)){
        std::filesystem::create_directory(final_output_directory);
    }
    for(auto &protocol : protocol_directories::payload_output_directory){
        std::filesystem::path payload_protocol_directory = final_output_directory.string() +
            std::string("/") + protocol.second;
            if(!std::filesystem::exists(payload_protocol_directory)){
                std::filesystem::create_directory(payload_protocol_directory);
            }
    }
    return true;
}
