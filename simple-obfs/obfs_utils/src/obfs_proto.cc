
#include "obfs_utils/obfs_proto.h"

void ObfsServer::DoHandshake(Peer &peer, NextStage next) {
    VLOG(1) << "start handshark";
    peer.socket.async_read_some(
        peer.buf.GetBuffer(),
        [this, &peer, next = std::move(next)](boost::system::error_code ec, size_t length) {
            if (ec) {
                if (ec == boost::asio::error::misc_errors::eof
                    || ec == boost::asio::error::operation_aborted) {
                    VLOG(1) << ec.message() << " while handshake";
                } else {
                    LOG(WARNING) << "unexcepted error while handshake: " << ec.message();
                }
                return;
            }

            peer.buf.Append(length);
            ssize_t valid_length = UnWrap(peer.buf);
            if (valid_length == 0) {
                VLOG(2) << length << " bytes read, but need more";
                DoHandshake(peer, std::move(next));
                return;
            } else if (valid_length < 0) {
                LOG(WARNING) << "handshake error";
                return;
            }

            obfs_->ResetTarget(target_);
            next();
        }
    );
}

