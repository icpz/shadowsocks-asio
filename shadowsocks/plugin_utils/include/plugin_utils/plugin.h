#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#include <memory>
#include <functional>
#include <boost/process.hpp>
#include <boost/asio.hpp>

struct Plugin {

    Plugin() : enable(false) { }

    bool Enabled() const { return enable; }

    bool enable;
    std::string remote_address;
    uint16_t remote_port;
    std::string local_address;
    uint16_t local_port;
    std::string plugin_options;
    std::string plugin;
};

std::unique_ptr<boost::process::child>
    StartPlugin(boost::asio::io_context &context,
                const Plugin &plugin,
                std::function<void(void)>&& OnExit);

uint16_t GetFreePort();

#endif

