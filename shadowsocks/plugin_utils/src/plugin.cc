
#include <boost/process/extend.hpp>

#include <common_utils/common.h>

#include "plugin_utils/plugin.h"

namespace bp = boost::process;
namespace ba = boost::asio;

struct PluginHandler : bp::extend::async_handler {

    PluginHandler(std::function<void(void)>&& OnExit)
        : on_exit_(OnExit) { }

    template<class Executor>
    auto on_exit_handler(Executor &exec) {
        return [on_exit_ = on_exit_, &exec](int exit_code, const std::error_code &ec) {
                   if (exit_code) {
                       LOG(ERROR) << "Plugin exits with code: " << exit_code
                                    << ", error code: " << ec;
                   } else {
                       LOG(INFO) << "Plugin exits with code: " << exit_code;
                   }
                   on_exit_();
               };
    }

    template<class Executor>
    void on_success(Executor &exec) {
        LOG(INFO) << "Plugin starts successfully";
    }

    template<class Executor>
    void on_error(Executor &exec, const std::error_code &ec) {
        LOG(ERROR) << "Plugin starts failed, error code: " << ec
                   << ", server terminates";
        on_exit_();
    }

    std::function<void(void)> on_exit_;

};

std::unique_ptr<bp::child>
    StartPlugin(ba::io_context &context, const Plugin &p, std::function<void(void)>&& OnExit) {

    if (!p.Enabled()) {
        return nullptr;
    }

    VLOG(2) << "starting plugin: " << p.plugin;
    
    bp::environment env = boost::this_process::environment();

    env["SS_REMOTE_HOST"] = p.remote_address;
    env["SS_REMOTE_PORT"] = std::to_string(p.remote_port);
    env["SS_LOCAL_HOST"] = p.local_address;
    env["SS_LOCAL_PORT"] = std::to_string(p.local_port);
    env["SS_PLUGIN_OPTIONS"] = p.plugin_options;

    auto c = std::make_unique<bp::child>(context, p.plugin,
                                         bp::cmd = p.plugin,
                                         PluginHandler(std::move(OnExit)),
                                         bp::env = env);
    return c;
}

uint16_t GetFreePort() {
    namespace ba = boost::asio;
    using boost::asio::ip::tcp;

    ba::io_context ctx;
    tcp::endpoint ep(tcp::v4(), 0);
    tcp::acceptor acceptor(ctx);
    acceptor.open(ep.protocol());
    acceptor.set_option(tcp::acceptor::reuse_address(true));
    acceptor.bind(ep);

    return acceptor.local_endpoint().port();
}

