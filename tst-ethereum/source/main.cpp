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


#include <boost/algorithm/string.hpp>

#include <boost/program_options/parsers.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

#include "executor.hpp"
#include "float.hpp"
#include "load.hpp"
#include "local.hpp"
#include "nested.hpp"
#include "signed.hpp"
#include "sleep.hpp"
#include "ticket.hpp"
#include "time.hpp"

namespace orc {

namespace po = boost::program_options;

static const Address OXT("0x4575f41308EC1483f3d399aa9a2826d74Da13Deb");

static const Float Two128(uint256_t(1) << 128);

bool Zeros(const Region &data) {
    return memchr(data.data(), '\0', data.size()) != nullptr;
}

template <size_t Size_>
Brick<Size_> Nonzero() {
    for (;;) {
        const auto value(Random<Size_>());
        if (!Zeros(value))
            return value;
    }
}

struct Tester {
    Endpoint &chain_;
    uint256_t chain_;

    const Executor &deployer_;
    const Executor &customer_;
    const Executor &provider_;

    task<Receipt> Receipt(const Bytes32 &transaction) {
        for (;;) {
            if (auto maybe{co_await chain_[transaction]}) {
                auto &receipt(*maybe);
                co_return std::move(receipt);
            }
            co_await Sleep(1000);
        }
    }

    task<bool> Audit(const std::string &name, const Bytes32 &transaction, uint64_t gas = 0) {
        const auto receipt(co_await Receipt(transaction));
        Log() << (receipt.status_ ? '+' : '-') << transaction << " " << name << ": " << std::dec << receipt.gas_ << " " << gas << " " << (gas == 0 ? 0 : int64_t(receipt.gas_) - int64_t(gas)) << std::endl;
        co_return receipt.status_;
    }

    task<void> Test0(const Secret &secret, const Address &signer, const Address &token, const Address &lottery, const Bytes &receipt) {
        Log() << "==========" << std::endl;
        Log() << "lottery0" << std::endl;

        static Selector<bool, Address, uint256_t> approve("approve");

        static const Selector<std::tuple<uint128_t, uint128_t, uint256_t, Address, Bytes32, Bytes>, Address, Address> look("look");
        static Selector<void, Address, uint128_t, uint128_t> push("push");

        static Selector<void,
            Bytes32 /*reveal*/, Bytes32 /*commit*/,
            uint256_t /*issued*/, Bytes32 /*nonce*/,
            uint8_t /*v*/, Bytes32 /*r*/, Bytes32 /*s*/,
            uint128_t /*amount*/, uint128_t /*ratio*/,
            uint256_t /*start*/, uint128_t /*range*/,
            Address /*funder*/, Address /*recipient*/,
            Bytes /*receipt*/, std::vector<Bytes32> /*old*/
        > grab("grab");

        const auto show([&]() -> task<void> {
            const auto [balance, escrow, unlock, verify, codehash, shared] = co_await look.Call(chain_, "latest", lottery, 90000, customer_, signer);
            Log() << std::dec << balance << " " << escrow << " | " << unlock << std::endl;
        });

        co_await Audit("approve", co_await customer_.Send(token, 0, approve(lottery, 10)));
        co_await Audit("push", co_await customer_.Send(lottery, 0, push(signer, 10, 4)));

        co_await show();

        const auto reveal(Nonzero<32>());
        const auto commit(Hash(reveal));

        const auto nonce(Nonzero<32>());

        const auto &funder(customer_);
        const auto &recipient(provider_);

        const uint128_t face(2);
        const uint128_t ratio(Float(Two128) - 1);

        const auto issued(Timestamp());
        const auto start(issued - 60);
        const uint128_t range(60 * 60 * 24);

        const Ticket ticket{commit, issued, nonce, face, ratio, start, range, funder, recipient};
        const auto hash(ticket.Encode0(lottery, chain_, receipt));
        const auto signature(Sign(secret, Hash(Tie("\x19""Ethereum Signed Message:\n32", hash))));

        co_await Audit("grab", co_await provider_.Send(lottery, 0, grab(reveal, commit, issued, nonce, signature.v_ + 27, signature.r_, signature.s_, face, ratio, start, range, funder, recipient, receipt, {})));

        co_await show();

        co_await Audit("approve", co_await customer_.Send(token, 0, approve(lottery, 10)));
        co_await Audit("push", co_await customer_.Send(lottery, 0, push(signer, 10, 0)));

        co_await show();
    }

    template <typename Gift_, typename Move_, typename ...Args_>
    task<void> Test1(const std::string &kind, const Address &lottery, Gift_ &&gift, Move_ &&move, Args_ ...args) {
        Log() << "==========" << std::endl;
        Log() << "lottery1 (" << kind << ")" << std::endl;

        static Selector<std::tuple<uint256_t, uint256_t, uint256_t>, Address, Address, Address, Args_...> read("read");
        static Selector<void, uint256_t, Bytes32> save("save");
        static Selector<void, Address, Args_..., uint128_t> warn("warn");

        typedef std::tuple<
            uint256_t /*random*/,
            uint256_t /*values*/,
            uint256_t /*packed*/,
            Bytes32 /*r*/, Bytes32 /*s*/
        > Payment;

        static Selector<void,
            Bytes32 /*refund*/,
            uint256_t /*destination*/,
            Payment /*ticket*/,
            Args_... /*token*/
        > claim1("claim1");

        static Selector<void,
            std::vector<Bytes32> /*refunds*/,
            uint256_t /*destination*/,
            std::vector<Payment> /*tickets*/,
            Args_... /*token*/
        > claimN("claimN");

        const auto indirect((co_await Receipt(co_await deployer_.Send(std::nullopt, 0, Contract<>(Bless(boost::replace_all_copy(Load("../lot-ethereum/build/OrchidRecipient.bin"), OXT.buf().hex().substr(2), lottery.buf().hex().substr(2))))))).contract_);

      secret:
        const auto secret(Random<32>());
        const Address signer(Commonize(secret));
        if (Zeros(signer.buf()))
            goto secret;

        const auto &funder(customer_);
        const auto &recipient(provider_);

        unsigned balance(0);
        unsigned escrow(0);

        const auto check([&](signed adjust) -> task<void> {
            balance += adjust;
            const auto [escrow_balance, unlock_warned, bound] = co_await read.Call(chain_, "latest", lottery, 90000, customer_, signer, 0, args...);
            //Log() << std::dec << uint128_t(escrow_balance) << " " << uint128_t(escrow_balance >> 128) << std::endl;
            orc_assert(uint128_t(escrow_balance) == balance);
            orc_assert(uint128_t(escrow_balance >> 128) == escrow);
            if (unlock_warned != 0) {
                const auto warned((uint128_t(unlock_warned)));
                const auto unlock(uint128_t(unlock_warned >> 128));
                Log() << std::dec << warned << " " << unlock << std::endl;
            }
        });


        const bool direct(false);

        const auto where([&]() -> uint256_t {
            return uint256_t(direct ? 1 : 0) << 255 | recipient.operator Address().num();
        });

        const auto payment([&]() {
            const auto reveal(Nonzero<16>().num<uint128_t>());
            const auto commit(Hash(Coder<uint128_t, uint256_t>::Encode(reveal, where())));

            const uint128_t face(1);
            const uint128_t ratio(Float(Two128) - 1);

            const auto issued(Timestamp() - 60);
            const auto start(issued + 20);
            const uint128_t range(60 * 60 * 16);

          sign:
            const auto salt(Nonzero<4>().num<uint32_t>());
            const auto nonce(Nonzero<32>());

            const Ticket ticket{commit, issued, nonce, face, ratio, start, range, funder, recipient};
            const auto signature(Sign(secret, ticket.Encode1<Args_...>(lottery, chain_, args..., salt, direct)));
            if (Zeros(signature.operator Brick<65>()))
                goto sign;

            return Payment(
                uint256_t(reveal) << 128 | uint128_t(nonce.num<uint256_t>()),
                ticket.Packed1(),
                ticket.Packed2() | uint256_t(salt) << 1 | signature.v_,
                signature.r_, signature.s_
            );
        });

        const auto payments([&](unsigned count) {
            std::vector<Payment> payments;
            payments.reserve(count);
            for (unsigned i(0); i != count; ++i)
                payments.emplace_back(payment());
            return payments;
        });


      seed:
        const auto seed(Nonzero<32>());
        const unsigned count(100);
        std::vector<Bytes32> saved; {
            auto refund(Hash(Coder<Bytes32, Address>::Encode(seed, recipient)));
            for (unsigned i(0); i != count; ++i) {
                if (!Zeros(refund))
                    saved.emplace_back(refund);
                refund = Hash(refund);
            }
        }
        if (saved.size() < 75)
            goto seed;
        co_await Audit("save", co_await recipient.Send(lottery, 0, save(count - 1, seed)));

        const auto refund([&]() {
            const auto refund(saved.back());
            saved.pop_back();
            return refund;
        });

        const auto refunds([&](unsigned count) {
            orc_assert(saved.size() >= count);
            std::vector<Bytes32> array(saved.end() - count, saved.end());
            saved.resize(saved.size() - count);
            return array;
        });


        co_await move(provider_, lottery, 1, provider_, 1, 0);

        co_await move(customer_, lottery, 10, signer, 4, 0);
        escrow += 4;
        co_await check(6);

        co_await gift(provider_, lottery, 75, customer_, signer);
        co_await check(75);

        static const unsigned per(3000+800+20000+800+7992);

        for (unsigned p(0); p != 4; ++p)
            for (unsigned d(0); d != (p+1)*2+1; ++d) {
                std::ostringstream name;
                name << "claimN(" << std::hex << std::uppercase << p << "," << d << ")";
                const auto positive(21000+1836 +per*p+(p==0?0:12+7400+4437) +(512+800+5000+265)*d+(d==0?0:12));
                auto negative(15000*d);
                if (negative > positive / 2) negative = positive / 2;
                co_await Audit(name.str(), co_await provider_.Send(lottery, 0, claimN(refunds(d), where(), payments(p), args...)), positive - negative);
                co_await check(-p);
            }

#if 0
        co_await Audit("claim1(1,0)", co_await provider_.Send(indirect, 0, claim1(Zero<32>(), where(), payment(), args...)), 33735+per);
        co_await check(-1);
#endif

        co_await Audit("claim1(1,0)", co_await provider_.Send(lottery, 0, claim1(Zero<32>(), where(), payment(), args...)), 33735+per);
        co_await check(-1);

        co_await Audit("claim1(1,1)", co_await provider_.Send(lottery, 0, claim1(refund(), where(), payment(), args...)), 25062+per);
        co_await check(-1);

        co_await move(customer_, lottery, 10, signer, 0, 0);
        co_await check(10);

        co_await Audit("warn", co_await customer_.Send(lottery, 0, warn(signer, args..., 4)));
        co_await check(0);

        co_await move(customer_, lottery, 0, signer, -4, 21);
        escrow -= 4;
        co_await check(4-21);
    }

    auto Combine(const checked_int256_t &adjust, const uint256_t &retrieve) {
        return Complement(adjust) << 128 | retrieve;
    }

    task<void> Test() {
        const auto lottery1eth((co_await Receipt(co_await deployer_.Send(std::nullopt, 0, Contract<>(Bless(Load("../lot-ethereum/build/OrchidLottery1eth.bin")))()))).contract_);
        const auto lottery1tok((co_await Receipt(co_await deployer_.Send(std::nullopt, 0, Contract<>(Bless(Load("../lot-ethereum/build/OrchidLottery1tok.bin")))()))).contract_);

#if 1
        static Selector<void, bool, std::vector<Address>> bind1("bind");
        co_await Audit("bind", co_await customer_.Send(lottery1eth, 0, bind1(false, {})));
        co_await Audit("bind", co_await customer_.Send(lottery1eth, 0, bind1(true, {provider_})));
#endif

#if 1
        static Selector<bool, Address, uint256_t> approve("approve");
        static Selector<uint256_t, Address> balanceOf("balanceOf");
        static Selector<bool, Address, uint256_t> transfer("transfer");
        static Selector<void, Address, uint256_t, Bytes> transferAndCall("transferAndCall");

      token:
        const auto token((co_await Receipt(co_await customer_.Send(std::nullopt, 0, Contract<>(Bless(Load("../tok-ethereum/build/OrchidToken677.bin")))()))).contract_);
        if (Zeros(token.buf()))
            goto token;

        const auto lottery1oxt((co_await Receipt(co_await deployer_.Send(std::nullopt, 0, Contract<>(Bless(boost::replace_all_copy(Load("../lot-ethereum/build/OrchidLottery1oxt.bin"), OXT.buf().hex().substr(2), token.buf().hex().substr(2))))()))).contract_);

        co_await Audit("transfer", co_await customer_.Send(token, 0, transfer(provider_, 500)));
        co_await Audit("transfer", co_await customer_.Send(token, 0, transfer(lottery1tok, 10)));
        co_await Audit("transfer", co_await customer_.Send(token, 0, transfer(lottery1oxt, 10)));

#if 1
      secret:
        const auto secret(Random<32>());
        const Address signer(Commonize(secret));
        if (Zeros(signer.buf()))
            goto secret;

        const auto lottery0((co_await Receipt(co_await deployer_.Send(std::nullopt, 0, Contract<Address>(Bless(Load("../lot-ethereum/build/OrchidLottery0.bin")))(token)))).contract_);
#if 1
        const auto verifier((co_await Receipt(co_await deployer_.Send(std::nullopt, 0, Contract<>(Bless(Load("../lot-ethereum/build/OrchidPassword.bin")))()))).contract_);
        static Selector<void, Address, Address, Bytes> bind0("bind");
        co_await Audit("bind", co_await customer_.Send(lottery0, 0, bind0(signer, verifier, {})));
        const Bytes receipt("password");
#else
        const Bytes receipt;
#endif
        co_await Test0(secret, signer, token, lottery0, receipt);
#endif

#if 1
        co_await Test1("erc20", lottery1tok, [&](const Executor &sender, const Address &lottery, const uint256_t &value, const Address &funder, const Address &signer) -> task<void> {
            static Selector<void, Address, Address, Address, uint256_t> gift("gift");
            co_await Audit("approve", co_await sender.Send(token, 0, approve(lottery, value)));
            co_await Audit("gift", co_await sender.Send(lottery, 0, gift(funder, signer, token, value)));
        }, [&](const Executor &sender, const Address &lottery, const uint256_t &value, const Address &signer, const checked_int256_t &adjust, const uint256_t &retrieve) -> task<void> {
            static Selector<void, Address, Address, uint256_t, uint256_t> move("move");
            if (value != 0)
                co_await Audit("approve", co_await sender.Send(token, 0, approve(lottery, value)));
            co_await Audit("move", co_await sender.Send(lottery, 0, move(signer, token, value, Combine(adjust, retrieve))));
        }, token);
#endif

#if 1
        co_await Test1("oxt", lottery1oxt, [&](const Executor &sender, const Address &lottery, const uint256_t &value, const Address &funder, const Address &signer) -> task<void> {
            static Selector<void, Address, Address, uint256_t> gift("gift");
            co_await Audit("approve", co_await sender.Send(token, 0, approve(lottery, value)));
            co_await Audit("gift", co_await sender.Send(lottery, 0, gift(funder, signer, value)));
        }, [&](const Executor &sender, const Address &lottery, const uint256_t &value, const Address &signer, const checked_int256_t &adjust, const uint256_t &retrieve) -> task<void> {
            static Selector<void, Address, uint256_t, uint256_t> move("move");
            if (value != 0)
                co_await Audit("approve", co_await sender.Send(token, 0, approve(lottery, value)));
            co_await Audit("move", co_await sender.Send(lottery, 0, move(signer, value, Combine(adjust, retrieve))));
        });
#endif

#if 1
        Log() << std::dec << co_await balanceOf.Call(chain_, "latest", token, 90000, lottery1tok) << std::endl;
        co_await Test1("erc677", lottery1tok, [&](const Executor &sender, const Address &lottery, const uint256_t &value, const Address &funder, const Address &signer) -> task<void> {
            static Selector<void, Address, Address> gift("gift");
            co_await Audit("gift", co_await sender.Send(token, 0, transferAndCall(lottery, value, Beam(gift(funder, signer)))));
        }, [&](const Executor &sender, const Address &lottery, const uint256_t &value, const Address &signer, const checked_int256_t &adjust, const uint256_t &retrieve) -> task<void> {
            Log() << std::dec << co_await balanceOf.Call(chain_, "latest", token, 90000, lottery1tok) << std::endl;
            static Selector<void, Address, uint256_t> move("move");
            co_await Audit("move", co_await sender.Send(token, 0, transferAndCall(lottery, value, Beam(move(signer, Combine(adjust, retrieve))))));
            Log() << std::dec << co_await balanceOf.Call(chain_, "latest", token, 90000, lottery1tok) << std::endl;
        }, token);
        Log() << std::dec << co_await balanceOf.Call(chain_, "latest", token, 90000, lottery1tok) << std::endl;
#endif
#endif

#if 1
        co_await Test1("ether", lottery1eth, [&](const Executor &sender, const Address &lottery, const uint256_t &value, const Address &funder, const Address &signer) -> task<void> {
            static Selector<void, Address, Address> gift("gift");
            co_await Audit("gift", co_await sender.Send(lottery, value, gift(funder, signer)));
        }, [&](const Executor &sender, const Address &lottery, const uint256_t &value, const Address &signer, const checked_int256_t &adjust, const uint256_t &retrieve) -> task<void> {
            static Selector<void, Address, uint256_t> move("move");
            co_await Audit("move", co_await sender.Send(lottery, value, move(signer, Combine(adjust, retrieve))));
        });
#endif
    }
};

task<int> Main(int argc, const char *const argv[]) {
    po::variables_map args;

    po::options_description group("general command line");
    group.add_options()
        ("help", "produce help message")
    ;

    po::options_description options;

    { po::options_description group("external resources");
    group.add_options()
        ("rpc", po::value<std::string>()->default_value("http://127.0.0.1:7545/"), "ethereum json/rpc private API endpoint")
    ; options.add(group); }

    po::store(po::parse_command_line(argc, argv, po::options_description()
        .add(group)
        .add(options)
    ), args);

    po::notify(args);

    if (args.count("help") != 0) {
        std::cout << po::options_description()
            .add(group)
            .add(options)
        << std::endl;
        co_return 0;
    }

    const auto origin(Break<Local>());
    Endpoint chain(origin, Locator::Parse(args["rpc"].as<std::string>()));

    std::vector<UnlockedExecutor> accounts;
    for (const auto &account : co_await chain("personal_listAccounts", {})) {
        Address address(account.asString());
        co_await chain("personal_unlockAccount", {address, "", 60u});
        accounts.emplace_back(chain, address);
    }

    uint256_t chain(co_await chain.Chain());
    Log() << std::dec << chain << std::endl;
    // XXX: work around a bug in Ganache
    if (chain == 1337) chain = 1;

    orc_assert(accounts.size() >= 3);
    Tester tester{chain, chain, accounts[0], accounts[1], accounts[2]};
    co_await tester.Test();

    co_return 0;
}

}

int main(int argc, char* argv[]) {
    _exit(orc::Wait(orc::Main(argc, argv)));
}
