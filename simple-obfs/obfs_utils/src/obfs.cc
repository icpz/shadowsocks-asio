
#include <boost/algorithm/string.hpp>

#include "obfs_utils/obfs.h"

using ObfsGenerator = ObfsGeneratorFactory::ObfsGenerator;

 std::shared_ptr<const ObfsArgs> Obfuscator::kArgs = nullptr;

boost::optional<ObfsGenerator>
    ObfsGeneratorFactory::GetGenerator(std::string name) {
        auto itr = generator_functions_.find(name);
        if (itr == generator_functions_.end()) {
            return boost::none;
        }
        return itr->second;
    }

std::shared_ptr<ObfsGeneratorFactory>
    ObfsGeneratorFactory::Instance() {
        static std::shared_ptr<ObfsGeneratorFactory>
                        self(new ObfsGeneratorFactory);
        return self;
    }

void ObfsGeneratorFactory::GetAllRegisteredNames(std::vector<std::string> &names) {
    names.resize(generator_functions_.size());
    std::transform(
        std::begin(generator_functions_),
        std::end(generator_functions_),
        names.begin(),
        [](const auto &kv) { return kv.first; }
    );
}

void ObfsArgs::ParseForwardOpt(std::string opt) {
    if (opt.empty()) return;
    std::vector<std::string> items;
    boost::split(items, opt, [](char c) { return c == ','; });
    for (auto &item : items) {
        std::vector<std::string> args;
        boost::split(args, item, boost::is_any_of("$%"));
        if (args.size() != 3) {
            continue;
        }

        boost::asio::ip::address address;
        boost::system::error_code ec;
        address = boost::asio::ip::make_address(args[1], ec);
        TargetInfo target;
        if (ec) {
            target.SetTarget(args[1], std::stoi(args[2]));
        } else {
            target.SetTarget(address, std::stoi(args[2]));
        }
        forward[args[0]] = std::move(target);
    }
}

