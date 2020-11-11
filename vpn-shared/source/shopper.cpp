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
#include "shopper.hpp"
#include "sleep.hpp"
#include "uniswap.hpp"
#include "updater.hpp"

namespace orc {

Shopper::Shopper(S<Updated<Float>> oracle) :
    Valve(typeid(*this).name()),
    oracle_(std::move(oracle))
{
}

task<S<Shopper>> Shopper::Create(unsigned milliseconds, S<Chain> chain) {
    co_return Break<Shopper>(co_await Opened(Updating(milliseconds, [chain]() -> task<Float> { try {
        static const Float Ten5("100000");
        const auto oracle(co_await Chainlink(*chain, "0x8bD3feF1abb94E6587fCC2C5Cb0931099D0893A0", Ten5));
        orc_assert(oracle != 0);
        // XXX: our Chainlink aggregation can have its answer forged by either Chainlink swapping the oracle set
        //      or by Orchid modifying the backend from our dashboard that Chainlink pays its oracles to consult
        co_return oracle > 0.10 ? 0.10 : oracle;
    } orc_catch({
        // XXX: our Chainlink aggregation has a remote killswitch in it left by Chainlink, so we need a fallback
        // XXX: figure out if there is a better way to detect this condition vs. another random JSON/RPC failure
        co_return 0.06;
    }) }, "Chainlink")));
}

task<void> Shopper::Shut() noexcept {
    co_await Valve::Shut();
}

}
