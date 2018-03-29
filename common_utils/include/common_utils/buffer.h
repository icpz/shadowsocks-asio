#ifndef __BUFFER_H__
#define __BUFFER_H__

#include <cstdint>
#include <vector>
#include <algorithm>
#include <boost/asio.hpp>

#include "common_utils/common.h"

class Buffer {
public:
    Buffer(size_t max_length = 8192)
        : buf_(std::max((size_t)1024, max_length)), curr_(0) {
    }

    void DeQueue(size_t len) {
        size_t total = curr_;
        if (len > total) {
            LOG(FATAL) << "Buffer::Dequeue len > total";
            len = total;
        }
        std::copy(Begin() + len, End(), Begin());
        curr_ = total - len;
    }

    void Append(size_t len) {
        PrepareCapacity(len);
        curr_ += len;
    }

    template<class Container>
    void AppendData(const Container &cont) {
        PrepareCapacity(cont.size());
        std::copy(std::begin(cont), std::end(cont), End());
        Append(cont.size());
    }

    void AppendData(const Buffer &buf) {
        PrepareCapacity(buf.Size());
        std::copy(buf.Begin(), buf.End(), End());
        Append(buf.Size());
    }

    void Reset(size_t new_len = 0) {
        ExpandCapacity(new_len);
        curr_ = new_len;
    }

    size_t Size() const {
        return curr_;
    }

    uint8_t *Begin() {
        return buf_.data();
    }

    const uint8_t *Begin() const {
        return buf_.data();
    }

    uint8_t *End() {
        return Begin() + Size();
    }

    const uint8_t *End() const {
        return Begin() + Size();
    }

    void PrepareCapacity(size_t more_length) {
        size_t total = Size() + more_length;
        if (total > Capacity()) {
            ExpandCapacity(total);
        }
    }

    void ExpandCapacity(size_t new_capacity) {
        if (Capacity() < new_capacity) {
            buf_.resize(new_capacity);
        }
    }

    size_t Capacity() const {
        return buf_.size();
    }

    boost::asio::mutable_buffer GetBuffer() {
        return boost::asio::buffer(End(), Capacity() - Size());
    }

    boost::asio::const_buffer GetConstBuffer() const {
        return boost::asio::buffer(Begin(), Size());
    }

    uint8_t *GetData() {
        return Begin();
    }

private:
    std::vector<uint8_t> buf_;
    size_t curr_;
};

#endif

