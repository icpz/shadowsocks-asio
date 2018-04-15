
#include <boost/endian/arithmetic.hpp>
#include <common_utils/socks5.h>

#include "ss_proto/client.h"

using boost::asio::ip::tcp;

uint8_t ShadowsocksClient::ParseHeader(Buffer &buf, size_t start_offset) {
    uint8_t reply = BasicProtocol::ParseHeader(buf, start_offset);
    if (reply != socks5::SUCCEEDED_REP) {
        return reply;
    }
    header_buf_.Append(buf.Size() - start_offset);
    std::copy(buf.Begin() + start_offset, buf.End(), header_buf_.Begin());
    return reply;
}

void ShadowsocksClient::DoInitializeProtocol(Peer &peer, NextStage next) {
    Wrap(header_buf_);
    boost::asio::async_write(
        peer.socket, header_buf_.GetConstBuffer(),
        [next](boost::system::error_code ec, size_t length) {
            if (ec) {
                if (ec == boost::asio::error::misc_errors::eof
                    || ec == boost::asio::error::operation_aborted) {
                    VLOG(1) << ec.message() << " while initializing protocol";
                } else {
                    LOG(WARNING) << "unexcepted error while initializing protocol: " << ec.message();
                }
                return;
            }
            next();
        }
    );
}

