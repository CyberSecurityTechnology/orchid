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


#include "chainlink.hpp"
#include "client.hpp"
#include "fiat.hpp"
#include "gauge.hpp"
#include "local.hpp"
#include "market.hpp"
#include "buyer.hpp"
#include "sleep.hpp"
#include "uniswap.hpp"
#include "updater.hpp"

namespace orc {

Buyer::Buyer(S<Market> market) :
    Valve(typeid(*this).name()),
    market_(std::move(market))
{
}

task<S<Buyer>> Buyer::Create(unsigned milliseconds, S<Chain> chain) {
    auto [fiat, gauge] = *co_await Parallel(
        UniswapFiat(milliseconds, chain),
        Opened(Make<Gauge>(milliseconds, chain->hack())));
    auto market(Make<Market>(std::move(fiat), std::move(gauge)));
    co_return Break<Buyer>(std::move(market));
}

task<void> Buyer::Shut() noexcept {
    co_await Valve::Shut();
}

}
