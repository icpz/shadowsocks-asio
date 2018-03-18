
#ifndef __BASIC_PROTOCOL_H__
#define __BASIC_PROTOCOL_H__

#include <memory>
#include <utility>
#include <functional>
#include <type_traits>
#include <boost/asio.hpp>
#include <boost/variant.hpp>

#include <common_utils/buffer.h>

class BasicProtocol {
    typedef boost::asio::ip::tcp tcp;
protected:
    using resolve_args_type = std::pair<std::string, std::string>;
    using target_info_type = boost::variant<tcp::endpoint, resolve_args_type>;
    using next_stage = std::function<void(void)>;

public:
    using wrap_function = std::function<ssize_t(Buffer &)>;

    BasicProtocol() : need_resolve_(false), initialized_(false) { }
    virtual ~BasicProtocol() { }

    virtual uint8_t ParseHeader(Buffer &buf);
    virtual ssize_t Wrap(Buffer &buf) { return buf.Size(); }
    virtual ssize_t UnWrap(Buffer &buf) { return buf.Size(); }
    virtual void DoInitializeProtocol(tcp::socket &socket, next_stage next) {
        initialized_ = true;
        next();
    }
    virtual tcp::endpoint GetEndpoint() const;
    virtual bool GetResolveArgs(std::string &hostname, std::string &port) const;
    virtual bool NeedResolve() const { return need_resolve_; }

protected:
    target_info_type target_;
    bool need_resolve_;
    bool initialized_;
};

template<typename ProtocolType, typename ...Args>
std::unique_ptr<BasicProtocol>
    GetProtocol(Args&& ...args) {
    static_assert(std::is_base_of<BasicProtocol, ProtocolType>::value, "ProtocolType must inherit from BasicProtocol");
    return std::make_unique<ProtocolType>(std::forward<Args>(args)...);
}

#endif

