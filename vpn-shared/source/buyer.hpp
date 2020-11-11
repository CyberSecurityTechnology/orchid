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


#ifndef ORCHID_BUYER_HPP
#define ORCHID_BUYER_HPP

#include <boost/random.hpp>
#include <boost/random/random_device.hpp>

#include "chain.hpp"
#include "float.hpp"
#include "jsonrpc.hpp"
#include "locator.hpp"
#include "origin.hpp"
#include "updated.hpp"
#include "valve.hpp"

namespace orc {

class Market;

class Buyer :
    public Valve
{
  private:
    const S<Market> market_;

  public:
    Buyer(S<Market> market, S<Updated<Float>> oracle);

    Buyer(const Buyer &) = delete;
    Buyer(Buyer &&) = delete;

    static task<S<Buyer>> Create(unsigned milliseconds, S<Chain> chain);

    task<void> Shut() noexcept override;
};

}

#endif//ORCHID_BUYER_HPP
