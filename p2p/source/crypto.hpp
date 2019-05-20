/* Orchid - WebRTC P2P VPN Market (on Ethereum)
 * Copyright (C) 2017-2019  The Orchid Authors
*/

/* GNU Affero General Public License, Version 3 {{{ */
/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
**/
/* }}} */


#ifndef ORCHID_CRYPTO_HPP
#define ORCHID_CRYPTO_HPP

#include "buffer.hpp"

#define _crycall(code) do { \
    orc_assert((code) == 0); \
} while (false)

namespace orc {

void Random(uint8_t *data, size_t size);

template <size_t Size_>
Brick<Size_> Random() {
    Brick<Size_> value;
    Random(value.data(), value.size());
    return value;
}

Brick<32> Hash(const Buffer &data);
Brick<32> Hash(const std::string &data);

}

#endif//ORCHID_CRYPTO_HPP
