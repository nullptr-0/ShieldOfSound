//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

/*
   Portions from http://www.adp-gmbh.ch/cpp/common/base64.html
   Copyright notice:

   base64.cpp and base64.h

   Copyright (C) 2004-2008 Rene Nyffenegger

   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   Rene Nyffenegger rene.nyffenegger@adp-gmbh.ch
*/

#ifndef BASE64_HPP
#define BASE64_HPP

#include <cctype>
#include <string>
#include <utility>
#include <cstdint>

namespace base64 {

    /// Returns max chars needed to encode a base64 string
    inline
        std::size_t constexpr
        encoded_size(std::size_t n);

    /// Returns max bytes needed to decode a base64 string
    inline
        std::size_t constexpr
        decoded_size(std::size_t n);

    char const*
        get_alphabet();

    signed char const*
        get_inverse();

    /** Encode a series of octets as a padded, base64 string.

        The resulting string will not be null terminated.

        @par Requires

        The memory pointed to by `out` points to valid memory
        of at least `encoded_size(len)` bytes.

        @return The number of characters written to `out`. This
        will exclude any null termination.
    */
    std::size_t
        encode(void* dest, void const* src, std::size_t len);

    /** Decode a padded base64 string into a series of octets.

        @par Requires

        The memory pointed to by `out` points to valid memory
        of at least `decoded_size(len)` bytes.

        @return The number of octets written to `out`, and
        the number of characters read from the input string,
        expressed as a pair.
    */
    std::pair<std::size_t, std::size_t>
        decode(void* dest, char const* src, std::size_t len);

} // base64

#include <vector>

std::string encodeVecToBase64(const std::vector<uint8_t>& input);

std::vector<uint8_t> decodeVecFromBase64(const std::string& input);

std::string encodeStrToBase64(const std::string& input);

std::string decodeStrFromBase64(const std::string& input);

#endif
