/*
Copyright 2022 The Photon Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include "photon/net/socket.h"

namespace photon {
namespace net {
namespace http {

struct Buffer {
    const void* ptr = 0;
    size_t size = 0;
    Buffer() = default;
    Buffer(const void* ptr, size_t size) : ptr(ptr), size(size) {}
    Buffer(std::string_view s) : ptr(s.data()), size(s.size()) {}
    operator iovec() const { return {(void*)ptr, size}; }
};

#define IS_LITTLE_ENDIAN 1

struct FrameHeader {
#if IS_LITTLE_ENDIAN
    uint8_t  type;
    uint32_t length : 24;
#else
    uint32_t length : 24;
    uint8_t  type;
#endif
    uint8_t  flags;
    uint32_t stream_id /*: 31*/;
    // uint8_t  reserved : 1;

#define DECLARE_FLAG(name, bit)                      \
    bool     name()   const { return flags & bit; }  \
    void     set_##name()   { flags |= bit; }        \

    DECLARE_FLAG(ack,         0x01);
    DECLARE_FLAG(end_stream,  0x01);
    DECLARE_FLAG(end_headers, 0x04);
    DECLARE_FLAG(padded,      0x08);
    DECLARE_FLAG(priority,    0x20);

#undef DECLARE_FLAG

    uint8_t padding() const { return padded() ? ext(0) : 0; }
    void padding(uint8_t padding) { set_padded(); ext(0) = padding; }

    constexpr static uint8_t DATA           = 0;
    constexpr static uint8_t HEADERS        = 1;
    constexpr static uint8_t PRIORITY       = 2;
    constexpr static uint8_t RST_STREAM     = 3;
    constexpr static uint8_t RESET_STREAM   = 3;
    constexpr static uint8_t SETTINGS       = 4;
    constexpr static uint8_t PUSH_PROMISE   = 5;
    constexpr static uint8_t PING           = 6;
    constexpr static uint8_t GOAWAY         = 7;
    constexpr static uint8_t WINDOW_UPDATE  = 8;
    constexpr static uint8_t CONTINUATION   = 9;

    constexpr static uint8_t NO_ERROR            = 0x00;
    constexpr static uint8_t PROTOCOL_ERROR      = 0x01;
    constexpr static uint8_t INTERNAL_ERROR      = 0x02;
    constexpr static uint8_t FLOW_CONTROL_ERROR  = 0x03;
    constexpr static uint8_t SETTINGS_TIMEOUT    = 0x04;
    constexpr static uint8_t STREAM_CLOSED       = 0x05;
    constexpr static uint8_t FRAME_SIZE_ERROR    = 0x06;
    constexpr static uint8_t REFUSED_STREAM      = 0x07;
    constexpr static uint8_t CANCEL              = 0x08;
    constexpr static uint8_t COMPRESSION_ERROR   = 0x09;
    constexpr static uint8_t CONNECT_ERROR       = 0x0a;
    constexpr static uint8_t ENHANCE_YOUR_CALM   = 0x0b;
    constexpr static uint8_t INADEQUATE_SECURITY = 0x0c;
    constexpr static uint8_t HTTP_1_1_REQUIRED   = 0x0d;

    constexpr static uint32_t MASK_31BIT = 0x7fffffff;

    // to access additional optional fields
    template<typename T = uint8_t>
    T& ext(size_t offset) {
        auto end = (char*)(this + 1);
        return *(T*)(end + offset);
    }
    template<typename T = uint8_t>
    const T& ext(size_t offset) const {
        auto end = (char*)(this + 1);
        return *(T*)(end + offset);
    }

    // conversion between network and host byte order
    void encode();
    void decode();
}__attribute__((packed));
static_assert(sizeof(FrameHeader) == 9, "");

struct DataFrameHeader : public FrameHeader {
    size_t   size()    const { return sizeof(FrameHeader) + padded(); }
}__attribute__((packed));
static_assert(sizeof(DataFrameHeader) == 9, "");

struct HeadersFrameHeader : public FrameHeader {
    size_t   size()       const { return sizeof(FrameHeader) + padded() + priority() * 5; }
    bool     exclusive()  const { return priority() ? (ext(padded()) >> 31) : 0; }
    uint32_t stream_dep() const { return priority() ? (ext<uint32_t>(padded()) & MASK_31BIT) : 0; }
    uint8_t  weight()     const { return priority() ?  ext(padded() + 4) : 0; }
    void     set_priority(uint32_t stream_dep, uint8_t exclusive, uint8_t weight) {
                    ext(padded()) = (exclusive << 31) | (stream_dep & MASK_31BIT);
                    ext(padded() + 4) = weight;
                    FrameHeader::set_priority();
    }
    void encode();
    void decode();
}__attribute__((packed));
static_assert(sizeof(HeadersFrameHeader) == 9, "");

struct PriorityFrameHeader : public FrameHeader {
    uint32_t stream_dependency : 31;
    uint8_t  exclusive : 1;
    uint8_t  weight;
    void encode();
    void decode();
    size_t   size()       const { return sizeof(*this); }
}__attribute__((packed));
static_assert(sizeof(PriorityFrameHeader) == 14, "");

struct ResetStreamFrameHeader : public FrameHeader {
    uint32_t error_code;
    void encode();
    void decode();
    size_t   size()       const { return sizeof(*this); }
}__attribute__((packed));
static_assert(sizeof(ResetStreamFrameHeader) == 13, "");

struct SettingsFrameHeader : public FrameHeader {
    struct Setting {
        uint16_t id;
        uint32_t value;
    }__attribute__((packed));

    constexpr static uint8_t SETTINGS_HEADER_TABLE_SIZE      = 1;
    constexpr static uint8_t SETTINGS_ENABLE_PUSH            = 2;
    constexpr static uint8_t SETTINGS_MAX_CONCURRENT_STREAMS = 3;
    constexpr static uint8_t SETTINGS_INITIAL_WINDOW_SIZE    = 4;
    constexpr static uint8_t SETTINGS_MAX_FRAME_SIZE         = 5;
    constexpr static uint8_t SETTINGS_MAX_HEADER_LIST_SIZE   = 6;

    void encode();
    void decode();
    void _bswap_all();

    size_t   size()       const { return sizeof(*this); }
    size_t   count()      const {
        assert(length >= sizeof(FrameHeader));
        if (length < sizeof(FrameHeader)) return 0;
        auto len = length - sizeof(FrameHeader);
        assert(len % sizeof(Setting) ==0);
        return len / sizeof(Setting);
    }
    Setting& operator[](size_t i) const {
        assert(i < count());
        return ((Setting*)&ext(0))[i];
    }
}__attribute__((packed));
static_assert(sizeof(SettingsFrameHeader) == 9, "");

struct PushPromiseFrameHeader : public FrameHeader {
    size_t   size()       const { return sizeof(*this) + padded() + 4; }
    const uint32_t& promise_stream_id() const { return ext<uint32_t>(padded()); }
    void set_promise_stream_id(uint32_t id) { ext<uint32_t>(padded()) = id & MASK_31BIT; }
    void encode();
    void decode();
}__attribute__((packed));
static_assert(sizeof(PushPromiseFrameHeader) == 9, "");

struct PingFrameHeader : public FrameHeader {
    char data[8];
    size_t   size()       const { return sizeof(*this); }
}__attribute__((packed));
static_assert(sizeof(PingFrameHeader) == 17, "");

struct GoawayFrameHeader : public FrameHeader {
    uint32_t last_stream_id /* : 31 */;
    // uint8_t  reserved : 1;
    uint32_t error_code;
    void encode();
    void decode();
    size_t   size()       const { return sizeof(*this); }
    bool has_additional_data() const { return length > size(); }
}__attribute__((packed));
static_assert(sizeof(GoawayFrameHeader) == 17, "");

struct WindowUpdateFrameHeader : public FrameHeader {
    uint32_t window_size_increment /* : 31 */;
    // uint8_t  reserved : 1;
    size_t   size()       const { return sizeof(*this); }
    void encode();
    void decode();
}__attribute__((packed));
static_assert(sizeof(WindowUpdateFrameHeader) == 13, "");

struct ContinuationFrameHeader : public FrameHeader {
    size_t   size()       const { return sizeof(*this); }
}__attribute__((packed));
static_assert(sizeof(ContinuationFrameHeader) == 9, "");

class Connection : public Object {
public:
    virtual int new_stream() = 0;

    virtual int accept_stream() = 0;

    // return frame size when success, including the frame header at *buf
    // otherwise return -1, and errno is set to indicate the error
    virtual int read_frame(int stream_id, void* buf, size_t len) = 0;

    // return frame size when success, including the frame header at *buf
    // otherwise return -1, and errno is set to indicate the error
    virtual int write_frame(int stream_id, const void* buf, size_t len) = 0;
};

Connection* new_connection(ISocketStream* socket, bool socket_ownership, bool is_client);

}
}
}
