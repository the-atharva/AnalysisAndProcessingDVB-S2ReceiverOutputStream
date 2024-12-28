#include <iostream>
#include <filesystem>
#include <string>

#include <cxxopts.hpp>
#include <fmt/core.h>
#include <fmt/color.h>

#include "ProcessDirectory.h"

int main(int argc, char **argv) {
    cxxopts::Options options("App", "Software application for analysis & "
                                    "processing DVB-S2 receiver oputput stream");
    options.add_options()("s,source", "Source directory for files",
                            cxxopts::value<std::string>())
                            ("d, destination", "Destination directory for output",
                            cxxopts::value<std::string>())
                            ("h,help", "Print usage");
    cxxopts::ParseResult result = options.parse(argc, argv);
    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        exit(0);
    }
    std::filesystem::directory_entry input_path;
    if(result.count("source")) input_path = std::filesystem::directory_entry(result["source"].as<std::string>());
    else {
        fmt::print(fg(fmt::color::red), "Source folder not provided\n");
        exit(1);
    }
    if(!std::filesystem::exists(input_path) || !std::filesystem::is_directory(input_path)){
        fmt::print(fg(fmt::color::red), "Invalid source file given\n");
        exit(1);
    }
    std::filesystem::directory_entry output_path;
    if(result.count("destination")) output_path = std::filesystem::directory_entry(result["destination"].as<std::string>());
    else {
        fmt::print (fg(fmt::color::red), "Destination folder not provided\n");
        exit(1);
    }
    if(!std::filesystem::exists(output_path) || !std::filesystem::is_directory(output_path)){
        fmt::print(fg(fmt::color::red), "Invalid destination file given\n");
        exit(1);
    }
    ProcessDirectory PD(input_path, output_path);
    PD.prepare_directories();
    PD.analyze_and_process();
    return 0;
}
// /home/a/Projects/Project/data
