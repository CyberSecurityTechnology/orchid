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


#ifndef ORCHID_NETWORK_HPP
#define ORCHID_NETWORK_HPP

#include <boost/random.hpp>
#include <boost/random/random_device.hpp>

#include "chain.hpp"
#include "jsonrpc.hpp"
#include "locator.hpp"
#include "origin.hpp"
#include "valve.hpp"

namespace orc {

class Client;
class Market;

struct Stake {
    uint256_t amount_;
    Maybe<std::string> url_;

    Stake(uint256_t amount, Maybe<std::string> url) :
        amount_(std::move(amount)),
        url_(std::move(url))
    {
    }
};

struct Provider {
    Address address_;
    Locator locator_;
    S<rtc::SSLFingerprint> fingerprint_;
};

class Network :
    public Valve
{
  private:
    const Chain chain_;
    const Address directory_;
    const Address location_;

    const S<Market> market_;
    const S<Updated<Float>> oracle_;

    boost::random::independent_bits_engine<boost::mt19937, 128, uint128_t> generator_;

  public:
    Network(Chain chain, Address directory, Address location, S<Market> market, S<Updated<Float>> oracle);

    Network(const Network &) = delete;
    Network(Network &&) = delete;

    static task<S<Network>> Create(unsigned milliseconds, Chain chain, Address directory, Address location);

    void Open();
    task<void> Shut() noexcept override;

    task<std::map<Address, Stake>> Scan();

    task<Provider> Select(const std::string &name, const Address &provider);

    // XXX: this should be task<Client &> but cppcoro doesn't seem to support that
    task<Client *> Connect(BufferSunk &sunk, const S<Origin> &origin, const Provider &provider, const Chain &chain, const Address &lottery, const Secret &secret, const Address &funder, const char *justin);
};

}

#endif//ORCHID_NETWORK_HPP
