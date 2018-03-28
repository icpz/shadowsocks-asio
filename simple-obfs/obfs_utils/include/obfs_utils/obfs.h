#ifndef __OBFS_H__
#define __OBFS_H__

#include <vector>
#include <functional>
#include <unordered_map>
#include <boost/optional.hpp>
#include <boost/utility/string_view.hpp>

#include <common_utils/buffer.h>

class Obfuscator {
    typedef boost::asio::ip::tcp tcp;
public:
    virtual ~Obfuscator() = default;

    virtual ssize_t ObfsRequest(Buffer &buf) = 0;
    virtual ssize_t DeObfsResponse(Buffer &buf) = 0;

    virtual ssize_t ObfsResponse(Buffer &buf) = 0;
    virtual ssize_t DeObfsRequest(Buffer &buf) = 0;

protected:
};

template<class ObfsType>
decltype(auto) MakeObfsGenerator(boost::string_view host) {
    static_assert(std::is_base_of<Obfuscator, ObfsType>::value, "The obfuscator type must inherit from Obfuscator");
    return [host]() { return std::unique_ptr<Obfuscator>(new ObfsType(host)); };
}

template<class Obfuscator>
class ObfsGeneratorRegister;

class ObfsGeneratorFactory {
public:
    using ObfsGenerator = std::function<std::unique_ptr<Obfuscator>(void)>;

    boost::optional<ObfsGenerator> GetGenerator(std::string name, boost::string_view host);

    static std::shared_ptr<ObfsGeneratorFactory> Instance();

    void GetAllRegisteredNames(std::vector<std::string> &names);

private:
    using ObfsGeneratorFunc = std::function<ObfsGenerator(boost::string_view host)>;

    ObfsGeneratorFactory() = default;
    std::unordered_map<std::string, ObfsGeneratorFunc> generator_functions_;

    void RegisterObfuscator(std::string name, ObfsGeneratorFunc gen) {
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
            [](boost::string_view host) {
                return MakeObfsGenerator<Obfuscator>(host);
            }
        );
    }
};

#endif

