#pragma once

#include "PcapFileDevice.h"

#include <cstdint>
#include <map>
#include <string>

namespace find_protocols {

    //Process directory
    enum class payload_protocols : uint8_t {
        UD = 0,
        GSE = 1,
        TS = 2

    };

    const std::map<find_protocols::payload_protocols, std::string> payload_protocol_string{
        {payload_protocols::GSE, std::string("Generic Stream Encapsulation")},
        {payload_protocols::TS, std::string("Transport Stream")},
        {payload_protocols::UD, std::string("Undetermined")}
    };

    const std::map<pcpp::ProtocolType, std::string> layer_protocol_string{
        {pcpp::Ethernet, std::string("Ethernet")},
        {pcpp::IPv4, std::string("IPv4")},
        {pcpp::ARP, std::string("ARP")},
        {pcpp::UDP, std::string("UDP")},
        {pcpp::GenericPayload, std::string("Generic Payload")},
        {pcpp::PacketTrailer, std::string("Packet Trailer")},
        {pcpp::DNS, std::string("DNS")}
    };

}

namespace protocol_extensions {
    const std::map<find_protocols::payload_protocols, std::string> payload_intermediate_extensions {
        {find_protocols::payload_protocols::GSE, std::string("bin")},
        {find_protocols::payload_protocols::TS, std::string("ts")}
    };

    const std::map<find_protocols::payload_protocols, std::string> payload_output_extensions {
        {find_protocols::payload_protocols::GSE, std::string("txt")},
        {find_protocols::payload_protocols::TS, std::string("mp4")}
    };
}

namespace protocol_directories {

        const std::map<find_protocols::payload_protocols, std::string> payload_output_directory {
        {find_protocols::payload_protocols::GSE, std::string("GSE")},
        {find_protocols::payload_protocols::TS, std::string("TS")}
    };
}

namespace directory_types {
    const std::string intermediate = "Intermediate";
    const std::string output = "Output";
}
