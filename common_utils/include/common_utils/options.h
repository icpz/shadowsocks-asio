#ifndef __COMMON_UTILS_OPTIONS_H__
#define __COMMON_UTILS_OPTIONS_H__

#include <memory>
#include <boost/program_options.hpp>

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
                    ("verbose", bpo::value<int>()->default_value(1),"Verbose log")
                    ("timeout", bpo::value<size_t>()->default_value(60), "Timeout in seconds")
                    ("help,h", "Print this help message");
                return desc;
            }();
        return desc;
    }

#endif // __COMMON_UTILS_OPTIONS_H__
