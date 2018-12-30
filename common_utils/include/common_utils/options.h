#ifndef __COMMON_UTILS_OPTIONS_H__
#define __COMMON_UTILS_OPTIONS_H__

#include <iostream>
#include <algorithm>
#include <memory>
#include <boost/program_options.hpp>

#include <cares_service/cares.hxx>

inline std::shared_ptr<boost::program_options::options_description>
    GetCommonOptions() {
        namespace bpo = boost::program_options;
        static auto desc = \
            [](){
                auto desc = std::make_shared<bpo::options_description>();
                desc->add_options()
                    ("bind-address,b", bpo::value<std::string>()->default_value("::"),
                        "Bind address")
                    ("bind-port,l", bpo::value<uint16_t>()->default_value(58888),
                        "Specific port that server will listen")
                    ("config-file,c", bpo::value<std::string>(), "Configuration file")
                    ("dns-servers,d", bpo::value<std::string>(), "Override system dns servers")
                    ("resolve-mode", bpo::value<std::string>(), "Resolve mode")
                    ("verbose", bpo::value<int>()->default_value(1),"Verbose log")
                    ("timeout", bpo::value<size_t>()->default_value(60), "Timeout in seconds")
                    ("help,h", "Print this help message");
                return desc;
            }();
        return desc;
    }

struct ResolverArgs {
    std::string servers;
    std::string mode;
};

inline void GetResolverArgs(const boost::program_options::variables_map &vm, ResolverArgs *args) {
    args->servers.clear();
    args->mode.clear();
    if (vm.count("dns-servers")) {
        args->servers = vm["dns-servers"].as<std::string>();
    }
    if (vm.count("resolve-mode")) {
        args->mode = vm["resolve-mode"].as<std::string>();
        auto avail_modes = cares::available_resolve_modes();
        auto itr = std::find(avail_modes.begin(), avail_modes.end(), args->mode);
        if (itr == avail_modes.end()) {
            std::cerr << "Invalid resolve mode: " << args->mode << std::endl
                      << "Available modes are: \n   ";
            for (auto &mode : avail_modes) {
                std::cerr << " " << mode;
            }
            std::cerr << std::endl;
            exit(-1);
        }
    }
}

#endif // __COMMON_UTILS_OPTIONS_H__
