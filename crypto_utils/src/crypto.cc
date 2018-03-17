
#include "crypto_utils/crypto.h"

using CtxGen = CryptoContextGeneratorFactory::CryptoContextGenerator;
boost::optional<CtxGen>
    CryptoContextGeneratorFactory::GetGenerator(std::string name, std::string password) {
        auto itr = generator_functions_.find(name);
        if (itr == generator_functions_.end()) {
            return boost::none;
        }
        return itr->second(password);
    }

std::shared_ptr<CryptoContextGeneratorFactory>
    CryptoContextGeneratorFactory::Instance() {
        static std::shared_ptr<CryptoContextGeneratorFactory> self(new CryptoContextGeneratorFactory);
        return self;
    }

