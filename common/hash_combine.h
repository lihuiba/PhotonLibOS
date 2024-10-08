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
#include <unordered_set>

namespace photon {

inline size_t hash_combine(size_t a) { return a; }

template<typename...Ts> inline
size_t hash_combine(size_t a, size_t b, Ts...xs) {
    auto x = (a<<6) + (a>>2) + 0x9e3779b9 + b;
    return hash_combine(x, xs...);
}

} // namespace photon
