
#include <boost/log/trivial.hpp>
#include "common_utils/buffer.h"

void Buffer::DeQueue(size_t len) {
    size_t total = curr_;
    if (len > total) {
        LOG(FATAL) << "Buffer::Dequeue len > total";
        len = total;
    }
    std::copy(Begin() + len, End(), Begin());
    curr_ = total - len;
}

