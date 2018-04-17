
#include <boost/algorithm/string.hpp>

#include "obfs_utils/obfs.h"

using ObfsGenerator = ObfsGeneratorFactory::ObfsGenerator;

std::shared_ptr<const ObfsArgs> Obfuscator::kArgs = nullptr;

void Obfuscator::SetObfsArgs(ArgsType args) {
    kArgs.reset(new ArgsType(std::move(args)));
}

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
    opt.erase(
        std::remove_if(opt.begin(), opt.end(), boost::is_any_of(" \t")),
        opt.end()
    );
    if (opt.empty()) return;
    std::vector<std::string> items;
    boost::split(items, opt, [](char c) { return c == ','; });
    for (auto &item : items) {
        std::vector<std::string> args;
        boost::split(args, item, boost::is_any_of("$"));
        if (args.size() != 2) {
            continue;
        }

        forward[args[0]] = MakeTarget(args[1], '%');
    }
}

