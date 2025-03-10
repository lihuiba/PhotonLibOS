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
#include <cstdint>
#include <photon/common/string_view.h>

uint32_t crc32c_sw(const uint8_t *buffer, size_t nbytes, uint32_t crc);

uint32_t crc32c_hw(const uint8_t *data, size_t nbytes, uint32_t crc);

/**
 * @brief We recommand using of crc32c() and crc32c_extend(), which can exploit hardware
 * acceleartion automatically. In case of using crc32c_hw() directly, please make sure invoking
 * is_crc32c_hw_available() to detect whether hardware acceleartion is available at first;
 *
 */
inline uint32_t crc32c_extend(const void *data, size_t nbytes, uint32_t crc) {
    extern uint32_t (*crc32c_auto)(const uint8_t *data, size_t nbytes, uint32_t crc);
    return crc32c_auto((uint8_t*)data, nbytes, crc);
}

inline uint32_t crc32c(const void *data, size_t nbytes) {
    return crc32c_extend((uint8_t*)data, nbytes, 0);
}

inline uint32_t crc32c_extend(std::string_view text, uint32_t crc) {
    return crc32c_extend(text.data(), text.size(), crc);
}

inline uint32_t crc32c(std::string_view text) {
    return crc32c_extend(text, 0);
}

inline bool is_crc32c_hw_available() {
    extern uint32_t (*crc32c_auto)(const uint8_t *data, size_t nbytes, uint32_t crc);
    return crc32c_auto != crc32c_sw;
}
