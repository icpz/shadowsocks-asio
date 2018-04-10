#ifndef __OBFS_H__
#define __OBFS_H__

#include <vector>
#include <functional>
#include <unordered_map>
#include <boost/optional.hpp>

#include <common_utils/util.h>

struct ObfsArgs {
    std::string obfs_host;
    uint16_t obfs_port;
    std::string obfs_uri;
};

class Obfuscator {
    typedef boost::asio::ip::tcp tcp;
public:
    using ArgsType = ObfsArgs;

    virtual ~Obfuscator() = default;

    virtual ssize_t ObfsRequest(Buffer &buf) = 0;
    virtual ssize_t DeObfsResponse(Buffer &buf) = 0;

    virtual ssize_t ObfsResponse(Buffer &buf) = 0;
    virtual ssize_t DeObfsRequest(Buffer &buf) = 0;

    virtual void ResetTarget(TargetInfo &target) {
    }

    static void SetObfsArgs(ArgsType args) {
        kArgs.reset(new ArgsType(std::move(args)));
    }
protected:
    static std::shared_ptr<const ArgsType> kArgs;
};

template<class ObfsType>
decltype(auto) MakeObfsGenerator() {
    static_assert(std::is_base_of<Obfuscator, ObfsType>::value, "The obfuscator type must inherit from Obfuscator");
    return []() { return std::unique_ptr<Obfuscator>(new ObfsType); };
}

template<class Obfuscator>
class ObfsGeneratorRegister;

class ObfsGeneratorFactory {
public:
    using ObfsGenerator = std::function<std::unique_ptr<Obfuscator>(void)>;

    boost::optional<ObfsGenerator> GetGenerator(std::string name);

    static std::shared_ptr<ObfsGeneratorFactory> Instance();

    void GetAllRegisteredNames(std::vector<std::string> &names);

private:
    ObfsGeneratorFactory() = default;
    std::unordered_map<std::string, ObfsGenerator> generator_functions_;

    void RegisterObfuscator(std::string name, ObfsGenerator gen) {
        auto itr = generator_functions_.find(name);
        if (itr != generator_functions_.end()) {
            throw std::runtime_error(name + " is already registered");
        }
        generator_functions_[name] = gen;
    }

    template<class T>
    friend class ObfsGeneratorRegister;
};

template<class Obfuscator>
class ObfsGeneratorRegister {
public:
    ObfsGeneratorRegister(std::string name) {
        auto factory = ObfsGeneratorFactory::Instance();
        factory->RegisterObfuscator( 
            name,
            MakeObfsGenerator<Obfuscator>()
        );
    }
};

#endif

