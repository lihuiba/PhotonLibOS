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

#include <inttypes.h>
#include <type_traits>
#include <memory>
#include <photon/common/conststr.h>
#include <photon/common/string_view.h>
#include <photon/common/utility.h>
#include <photon/common/alog.h>

#undef  LOG_ERROR_RETURN
#define LOG_ERROR_RETURN(a, b, ...) return b;

namespace photon {
namespace net {
namespace http {

template<size_t N>
struct Octet {
    static_assert(1 <= N && N <= 8, "N must be in [1, 8]");
    uint8_t value : N;
    uint8_t flags : 8 - N;
    constexpr static uint8_t max_value = (1U << N) - 1;
    operator uint8_t() {
        static_assert(sizeof(*this) == 1, "sizeof(Octet) must be 1");
        return *(uint8_t*)this;
    }
}__attribute__((packed));


inline uint8_t make_octet(uint8_t value, uint8_t flags, uint8_t prefix_length) {
    assert(1 <= prefix_length && prefix_length <= 8);
    assert(flags < (1U << (8 - prefix_length)));
    assert(value < (1U << prefix_length));
    return value | (flags << prefix_length);
}

static void encode_integer(char*& ptr, uint8_t flags, uint8_t prefix_length, uint64_t x) {
    assert(1 <= prefix_length && prefix_length <= 8);
    assert(flags < (1U << (8 - prefix_length)));
    auto max_prefix = (1U << prefix_length) - 1U;
    if (x < max_prefix) {
        *ptr++ = make_octet(x, flags, prefix_length);
    } else {
        *ptr++ = make_octet(max_prefix, flags, prefix_length);
        x -= max_prefix;
        while (x >= 128) {
            *ptr++ = x % 128 + 128;
            x /= 128;
        }
        *ptr++ = x;
    }
}

struct integer {
    uint64_t value;
    uint8_t flags;
    operator uint64_t() const { return value; }
};

static integer decode_integer(const char*& ptr, uint8_t prefix_length) {
    uint8_t octet = *ptr++;
    uint8_t flags = octet >> prefix_length;
    uint8_t mask = (1U << prefix_length) - 1;
    uint8_t prefix = octet & mask;
    if (prefix < mask)
        return {prefix, flags};

    uint64_t x = 0;
    for (int i = 9; i; --i) {
        uint8_t next = *ptr++;
        if (next >= 128) {
            x += next - 128;
            x *= 128;
        } else {
            x += next;
            break;
        }
    };
    return {prefix + x, flags};
}

#include "huffman_code.i"

inline uint8_t bswap(char x) { return x; }
inline uint32_t bswap(uint32_t x) { return __builtin_bswap32(x); }

static ssize_t huffman_encode(std::string_view src, char* dst, const char* dst_end) {
    uint64_t x = 0, coded = 0;
    auto output = [&](auto*& ptr) {
        const auto nbits = sizeof(*ptr) * 8;
        if (unlikely(coded >= nbits)) {
            coded -= nbits;
            if (likely((char*)ptr < dst_end)) {
                using T = typename std::remove_reference<decltype(*ptr)>::type;
                *ptr++ = bswap((T)(x >> coded));
            }
            x &= (1ULL << coded) - 1;
        }
    };

    dst_end -= 4;
    auto p = (uint32_t*)dst;
    for (auto c : src) {
        assert((huffman_code[c] >> code_length[c]) == 0);
        x = (x << code_length[c]) | huffman_code[c];
        coded += code_length[c];
        output(p);
    }
    dst_end += 4;

    auto pc = (char*)p;
    while (coded >= 8)
        output(pc);
    if (coded) {
        assert(coded < 8);
        auto padding = 8 - coded;
        x = (x << padding) | ((1ULL << padding) - 1);
        coded = 8;
        output(pc);
    }
    return pc - dst;
}

#include "huffman_tree.i"

static ssize_t huffman_decode(std::string_view src, char* dst,
            const char* dst_end, uint16_t* start_node = nullptr) {
    auto p = dst;
    auto t = huffman_tree;
    if (start_node) {
        t += *start_node;
        assert(*start_node < LEN(huffman_tree) && !t->isleaf());
    }
    for (size_t i = 0; i < src.size(); ++i) {
        signed char c = src[i];
        for (uint8_t n = 8; n; --n) {
            assert(!t->isleaf());
            auto nx = t->next[c < 0]; // test most-significant bit
            c = (signed char)(((uint8_t)c) << 1);
            if (nx == 0) {
                assert(t == &huffman_tree[EOS_Node]);
                break;
            }
            t += nx;
            if (t >= huffman_tree + LEN(huffman_tree))
                LOG_ERROR_RETURN(EINVAL, -1, "invalid input data");
            if (unlikely(t->isleaf())) {
                if (p >= dst_end)
                    LOG_ERROR_RETURN(ENOBUFS, -1, "dst buffer too small");
                *p++ = t->get_symbol();
                t = huffman_tree;
            }
        }
    }
    if (start_node)
        *start_node = t - huffman_tree;
    return p - dst;
}

struct HuffmanDecodeEntry {
    uint8_t next_state = 0;
    uint8_t num_symbols = 0;
    uint8_t symbols[2] = {0, 0};
};

struct _HuffmanDecodeTable {
    HuffmanDecodeEntry huffman_decode_table[256][256];
    _HuffmanDecodeTable() {
        uint16_t num_states = 0;
        uint8_t state_map[LEN(huffman_tree)];
        uint16_t reverse_map[LEN(huffman_tree) / 2];
        // Collect all non-leaf nodes as reachable states and build state mapping
        for (size_t i = 0; i < LEN(huffman_tree); ++i) {
            if (!huffman_tree[i].isleaf()) {
                state_map[i] = num_states;
                assert(num_states < LEN(reverse_map));
                reverse_map[num_states++] = i;
            }
        }
        // Fill decode table using huffman_decode
        for (size_t idx = 0; idx < num_states; ++idx) {
            for (int byte = 0; byte < 256; ++byte) {
                auto& entry = huffman_decode_table[idx][byte];
                uint16_t state = reverse_map[idx];
                entry.num_symbols = huffman_decode({(char*)&byte, 1}, (char*)entry.symbols,
                                          (char*)entry.symbols + 2, &state);
                assert(entry.num_symbols < 3);
                entry.next_state = state_map[state];
            }
        }
    }
};

typedef HuffmanDecodeEntry (*HuffmanDecodeTable)[256];

inline const HuffmanDecodeTable get_huffman_decode_table() {
    const static auto t = std::make_unique<_HuffmanDecodeTable>();
    return t->huffman_decode_table;
}

ssize_t huffman_decode_fast(std::string_view src, char* dst, const char* dst_end) {
    auto p = dst;
    uint8_t state = 0;
    auto huffman_decode_table = get_huffman_decode_table();
    for (uint8_t c : src) {
        const auto& entry = huffman_decode_table[state][c];
        if (entry.next_state == 0xFF)
            LOG_ERROR_RETURN(EINVAL, -1, "invalid input data");
        auto n = entry.num_symbols;
        if (p + n > dst_end)
            LOG_ERROR_RETURN(ENOBUFS, -1, "dst buffer too small");
        if (likely(n == 1)) *p++ = entry.symbols[0];
        else if (likely(n == 2)) *((uint16_t*&)p)++ = *(uint16_t*)entry.symbols;
        else assert(n == 0);
        state = entry.next_state;
    }
    return p - dst;
}

const static auto static_header_names = ConstString::make_compact_str_array<uint16_t>(
    /* 0  */  TSTRING("_"),
    /* 1  */  TSTRING(":authority"),
    /* 2  */  TSTRING(":method"),
    /* 3  */  TSTRING(":method"),
    /* 4  */  TSTRING(":path"),
    /* 5  */  TSTRING(":path"),
    /* 6  */  TSTRING(":scheme"),
    /* 7  */  TSTRING(":scheme"),
    /* 8  */  TSTRING(":status"),
    /* 9  */  TSTRING(":status"),
    /* 10 */  TSTRING(":status"),
    /* 11 */  TSTRING(":status"),
    /* 12 */  TSTRING(":status"),
    /* 13 */  TSTRING(":status"),
    /* 14 */  TSTRING(":status"),
    /* 15 */  TSTRING("accept-charset"),
    /* 16 */  TSTRING("accept-encoding"),
    /* 17 */  TSTRING("accept-language"),
    /* 18 */  TSTRING("accept-ranges"),
    /* 19 */  TSTRING("accept"),
    /* 20 */  TSTRING("access-control-allow-origin"),
    /* 21 */  TSTRING("age"),
    /* 22 */  TSTRING("allow"),
    /* 23 */  TSTRING("authorization"),
    /* 24 */  TSTRING("cache-control"),
    /* 25 */  TSTRING("content-disposition"),
    /* 26 */  TSTRING("content-encoding"),
    /* 27 */  TSTRING("content-language"),
    /* 28 */  TSTRING("content-length"),
    /* 29 */  TSTRING("content-location"),
    /* 30 */  TSTRING("content-range"),
    /* 31 */  TSTRING("content-type"),
    /* 32 */  TSTRING("cookie"),
    /* 33 */  TSTRING("date"),
    /* 34 */  TSTRING("etag"),
    /* 35 */  TSTRING("expect"),
    /* 36 */  TSTRING("expires"),
    /* 37 */  TSTRING("from"),
    /* 38 */  TSTRING("host"),
    /* 39 */  TSTRING("if-match"),
    /* 40 */  TSTRING("if-modified-since"),
    /* 41 */  TSTRING("if-none-match"),
    /* 42 */  TSTRING("if-range"),
    /* 43 */  TSTRING("if-unmodified-since"),
    /* 44 */  TSTRING("last-modified"),
    /* 45 */  TSTRING("link"),
    /* 46 */  TSTRING("location"),
    /* 47 */  TSTRING("max-forwards"),
    /* 48 */  TSTRING("proxy-authenticate"),
    /* 49 */  TSTRING("proxy-authorization"),
    /* 50 */  TSTRING("range"),
    /* 51 */  TSTRING("referer"),
    /* 52 */  TSTRING("refresh"),
    /* 53 */  TSTRING("retry-after"),
    /* 54 */  TSTRING("server"),
    /* 55 */  TSTRING("set-cookie"),
    /* 56 */  TSTRING("strict-transport-security"),
    /* 57 */  TSTRING("transfer-encoding"),
    /* 58 */  TSTRING("user-agent"),
    /* 59 */  TSTRING("vary"),
    /* 60 */  TSTRING("via"),
    /* 61 */  TSTRING("www-authenticate"));

const static auto static_header_values = ConstString::make_compact_str_array<uint16_t>(
    TSTRING("_"),
    TSTRING(""),
    TSTRING("GET"),
    TSTRING("POST"),
    TSTRING("/"),
    TSTRING("/index.html"),
    TSTRING("http"),
    TSTRING("https"),
    TSTRING("200"),
    TSTRING("204"),
    TSTRING("206"),
    TSTRING("304"),
    TSTRING("400"),
    TSTRING("404"),
    TSTRING("500"),
    TSTRING(""),
    TSTRING("gzip, deflate"));

static std::string_view lookup_static_table(size_t i) {
    if (i > 16) return {};
    return static_header_values.at(i);
}

int asdf(uint64_t x) {
    char buf[100]{};
    char* ptr = buf;
    encode_integer(ptr, 0b1, 1, x);
    ptr = buf;
    return decode_integer((const char*&)ptr, 1);
}

static void test_huffman() {
    const static std::string_view huffman[][2] = {
        {"302", "\x64\x02"},
        {"307", "\x64\x0e\xff"},
        {"gzip", "\x9b\xd9\xab"},
        {"private", "\xae\xc3\x77\x1a\x4b"},
        {"no-cache", "\xa8\xeb\x10\x64\x9c\xbf"},
        {"custom-key", "\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f"},
        {"custom-value", "\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf"},
        {"www.example.com", "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"},
        {"https://www.example.com", "\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3"},
        {"Mon, 21 Oct 2013 20:13:21 GMT", "\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff"},
        {"Mon, 21 Oct 2013 20:13:22 GMT", "\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x84\xa6\x2d\x1b\xff"},
        {"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", "\x94\xe7\x82\x1d\xd7\xf2\xe6\xc7\xb3\x35\xdf\xdf\xcd\x5b\x39\x60\xd5\xaf\x27\x08\x7f\x36\x72\xc1\xab\x27\x0f\xb5\x29\x1f\x95\x87\x31\x60\x65\xc0\x03\xed\x4e\xe5\xb1\x06\x3d\x50\x07"},
    };
    char buf[400];
    for (auto& x: huffman) {
        auto len = huffman_encode(x[0], buf, buf + sizeof(buf));
        std::string_view coded = {buf, (size_t)len};
        assert(x[1] == coded);

        len = huffman_decode(x[1], buf, buf + sizeof(buf));
        assert(x[0] == std::string_view(buf, (size_t)len));

        len = huffman_decode_fast(x[1], buf, buf + sizeof(buf));
        assert(x[0] == std::string_view(buf, (size_t)len));
    }
}


}
}
}

int main() {
    photon::net::http::test_huffman();
    return 0;
}