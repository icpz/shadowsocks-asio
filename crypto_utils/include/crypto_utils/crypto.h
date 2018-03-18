#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <vector>
#include <unordered_map>
#include <boost/optional.hpp>

#include "crypto_utils/cipher.h"

template<class Cipher>
class CryptoContextGeneratorRegister;

class CryptoContextGeneratorFactory {
public:
    using CryptoContextGenerator
            = std::function<std::unique_ptr<CryptoContext>(void)>;
    boost::optional<CryptoContextGenerator>
            GetGenerator(std::string name, std::string password);

    static std::shared_ptr<CryptoContextGeneratorFactory> Instance();

    void GetAllRegisteredNames(std::vector<std::string> &names);

private:
    using CryptoContextGeneratorFunc
            = std::function<CryptoContextGenerator(std::string)>;

    CryptoContextGeneratorFactory() = default;
    std::unordered_map<std::string, CryptoContextGeneratorFunc> generator_functions_;

    void RegisterContext(std::string name, CryptoContextGeneratorFunc func) {
        auto itr = generator_functions_.find(name);
        if (itr != generator_functions_.end()) {
            throw std::runtime_error(name + " is already registered");
        }
        generator_functions_[name] = func;
    }

    template<class T>
    friend class CryptoContextGeneratorRegister;
};

template<class Cipher>
class CryptoContextGeneratorRegister {
public:
    CryptoContextGeneratorRegister(std::string name) {
        auto factory = CryptoContextGeneratorFactory::Instance();
        factory->RegisterContext(
            name,
            std::bind(&MakeCryptoContextGenerator<Cipher>, std::placeholders::_1)
        );
    }
};

#endif

