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


#include <openssl/obj_mac.h>

#include "chain.hpp"
#include "chainlink.hpp"
#include "client.hpp"
#include "fiat.hpp"
#include "gauge.hpp"
#include "local.hpp"
#include "market.hpp"
#include "network.hpp"
#include "sequence.hpp"
#include "sleep.hpp"
#include "uniswap.hpp"
#include "updater.hpp"

namespace orc {

Network::Network(Chain chain, Address directory, Address location, S<Market> market, S<Updated<Float>> oracle) :
    Valve(typeid(*this).name()),
    chain_(std::move(chain)),
    directory_(std::move(directory)),
    location_(std::move(location)),
    market_(std::move(market)),
    oracle_(std::move(oracle))
{
    generator_.seed(boost::random::random_device()());
}

void Network::Open() {
}

task<void> Network::Shut() noexcept {
    co_await Valve::Shut();
}

task<S<Network>> Network::Create(unsigned milliseconds, Chain chain, Address directory, Address location) {
    auto temp(Opened(Updating(milliseconds, [chain]() -> task<Float> { try {
        static const Float Ten5("100000");
        const auto oracle(co_await Chainlink(chain, "0x8bD3feF1abb94E6587fCC2C5Cb0931099D0893A0", Ten5));
        orc_assert(oracle != 0);
        // XXX: our Chainlink aggregation can have its answer forged by either Chainlink swapping the oracle set
        //      or by Orchid modifying the backend from our dashboard that Chainlink pays its oracles to consult
        co_return oracle > 0.10 ? 0.10 : oracle;
    } orc_catch({
        // XXX: our Chainlink aggregation has a remote killswitch in it left by Chainlink, so we need a fallback
        // XXX: figure out if there is a better way to detect this condition vs. another random JSON/RPC failure
        co_return 0.06;
    }) }, "Chainlink")));

    auto [fiat, gauge, oracle] = *co_await Parallel(
        UniswapFiat(milliseconds, chain),
        Opened(Make<Gauge>(milliseconds, chain.hack())),
        std::move(temp));
    auto market(Make<Market>(std::move(fiat), std::move(gauge)));

    auto network(Break<Network>(std::move(chain), std::move(directory), std::move(location), std::move(market), std::move(oracle)));
    network->Open();
    co_return std::move(network);
}

template <typename Code_>
task<void> Stakes(const Chain &chain, const Address &directory, const Block &block, const uint256_t &storage, const uint256_t &primary, const Code_ &code) {
    if (primary == 0)
        co_return;

    const auto stake(Hash(Tie(primary, uint256_t(0x2U))).num<uint256_t>());
    const auto [left, right, stakee, amount, delay] = co_await chain.Get(block, directory, storage, stake + 6, stake + 7, stake + 4, stake + 2, stake + 3);
    orc_assert(amount != 0);

    *co_await Parallel(
        Stakes(chain, directory, block, storage, left, code),
        Stakes(chain, directory, block, storage, right, code),
        code(uint160_t(stakee), amount, delay));
}

template <typename Code_>
task<void> Stakes(const Chain &chain, const Address &directory, const Code_ &code) {
    const auto height(co_await chain.Height());
    const auto block(co_await chain.Header(height));
    const auto [account, root] = co_await chain.Get(block, directory, nullptr, 0x3U);
    co_await Stakes(chain, directory, block, account.storage_, root, code);
}

task<std::map<Address, Stake>> Network::Scan() {
    cppcoro::async_mutex mutex;
    std::map<Address, uint256_t> stakes;

    co_await Stakes(chain_, directory_, [&](const Address &stakee, const uint256_t &amount, const uint256_t &delay) -> task<void> {
        std::cout << "DELAY " << stakee << " " << std::dec << delay << " " << std::dec << amount << std::endl;
        if (delay < 90*24*60*60)
            co_return;
        const auto lock(co_await mutex.scoped_lock_async());
        stakes[stakee] += amount;
    });

    // XXX: Zip doesn't work if I inline this argument
    const auto urls(co_await Parallel(Map([&](const auto &stake) {
        return [&](Address provider) -> Task<std::string> {
            static const Selector<std::tuple<uint256_t, Bytes, Bytes, Bytes>, Address> look_("look");
            const auto &[set, url, tls, gpg] = co_await look_.Call(chain_, "latest", location_, 90000, provider);
            orc_assert(set != 0);
            co_return url.str();
        }(stake.first);
    }, stakes)));

    std::map<Address, Stake> providers;

    // XXX: why can't I move things out of this iterator? (note: I did use auto)
    for (const auto &stake : Zip(urls, stakes))
        orc_assert(providers.try_emplace(stake.get<1>().first, stake.get<1>().second, stake.get<0>()).second);

    co_return providers;
}

task<Provider> Network::Select(const std::string &name, const Address &provider) {
    //co_return Provider{"0x2b1ce95573ec1b927a90cb488db113b40eeb064a", "https://local.saurik.com:8084/", rtc::SSLFingerprint::CreateUniqueFromRfc4572("sha-256", "A9:E2:06:F8:42:C2:2A:CC:0D:07:3C:E4:2B:8A:FD:26:DD:85:8F:04:E0:2E:90:74:89:93:E2:A5:58:53:85:15")};

    // XXX: this adjustment is suboptimal; it seems to help?
    //const auto latest(co_await chain_.Latest() - 1);
    //const auto block(co_await chain_.Header(latest));
    // XXX: Cloudflare's servers are almost entirely broken
    static const std::string latest("latest");

    // XXX: parse the / out of name (but probably punt this to the frontend)
    Beam argument;
    const auto curator(co_await chain_.Resolve(latest, name));

    const auto address(co_await [&]() -> task<Address> {
        if (provider != Address(0))
            co_return provider;

        static const Selector<std::tuple<Address, uint128_t>, uint128_t> pick_("pick");
        const auto [address, delay] = co_await pick_.Call(chain_, latest, directory_, 90000, generator_());
        orc_assert(delay >= 90*24*60*60);
        co_return address;
    }());

    static const Selector<uint128_t, Address, Bytes> good_("good");
    static const Selector<std::tuple<uint256_t, Bytes, Bytes, Bytes>, Address> look_("look");

    const auto [good, look] = *co_await Parallel(
        good_.Call(chain_, latest, curator, 90000, address, argument),
        look_.Call(chain_, latest, location_, 90000, address));
    const auto &[set, url, tls, gpg] = look;

    orc_assert(good != 0);
    orc_assert(set != 0);

    Window window(tls);
    orc_assert(window.Take() == 0x06);
    window.Skip(Length(window));
    const Beam fingerprint(window);

    static const std::map<Beam, std::string> algorithms_({
        {Object(NID_md2), "md2"},
        {Object(NID_md5), "md5"},
        {Object(NID_sha1), "sha-1"},
        {Object(NID_sha224), "sha-224"},
        {Object(NID_sha256), "sha-256"},
        {Object(NID_sha384), "sha-384"},
        {Object(NID_sha512), "sha-512"},
    });

    const auto algorithm(algorithms_.find(Window(tls).Take(tls.size() - fingerprint.size())));
    orc_assert(algorithm != algorithms_.end());
    co_return Provider{address, Locator::Parse(url.str()), std::make_shared<rtc::SSLFingerprint>(algorithm->second, fingerprint.data(), fingerprint.size())};
}

task<Client *> Network::Connect(BufferSunk &sunk, const S<Origin> &origin, const Provider &provider, const Chain &chain, const Address &lottery, const Secret &secret, const Address &funder, const char *justin) {
    static const Selector<std::tuple<uint128_t, uint128_t, uint256_t, Address, Bytes32, Bytes>, Address, Address> look_("look");
    const auto [amount, escrow, unlock, seller, codehash, shared] = co_await look_.Call(chain, "latest", lottery, 90000, funder, Address(Commonize(secret)));
    orc_assert(unlock == 0);

    auto &client(sunk.Wire<Client>(
        provider.locator_, provider.fingerprint_,
        market_, oracle_,
        chain, lottery,
        secret, funder,
        seller, std::min(amount, escrow / 2),
        justin
    ));

    co_await client.Open(origin);
    co_return &client;
}

}
