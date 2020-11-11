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
#include "signed.hpp"
#include "sleep.hpp"
#include "ticket.hpp"

namespace orc {

namespace po = boost::program_options;

uint256_t bid_(0);
S<Chain> chain_;
S<Executor> executor_;
std::optional<uint256_t> nonce_;
Locator rpc_{"http", "127.0.0.1", "8545", "/"};

class Args :
    public std::deque<std::string>
{
  public:
    Args() = default;

    Args(std::initializer_list<std::string> args) {
        for (auto &arg : args)
            emplace_back(arg);
    }

    Args(int argc, const char *const argv[]) {
        for (int arg(0); arg != argc; ++arg)
            emplace_back(argv[arg]);
    }

    operator bool() {
        return !empty();
    }

    auto operator ()() {
        orc_assert(!empty());
        const auto value(std::move(front()));
        pop_front();
        return value;
    }
};

template <typename Type_>
struct Option;

template <typename Type_>
struct Option<std::optional<Type_>> {
static std::optional<Type_> Parse(Args &args) {
    return Option<Type_>::Parse(args);
} };

template <>
struct Option<bool> {
static bool Parse(Args &args) {
    const auto arg(args());
    if (false);
    else if (arg == "true")
        return true;
    else if (arg == "false")
        return false;
    orc_assert_(false, "invalid bool " << arg);
} };

template <>
struct Option<std::string> {
static std::string Parse(Args &args) {
    return args();
} };

template <>
struct Option<Bytes32> {
static Bytes32 Parse(Args &args) {
    return Bless(args());
} };

template <>
struct Option<uint256_t> {
static uint256_t Parse(Args &args) {
    auto arg(args());
    Float shift(1);

    auto last(arg.size());
    for (;;) {
        orc_assert(last-- != 0);
        if (false);
        else if (arg[last] == 'G')
            shift *= Ten9;
        else break;
    }

    if (shift == 1)
        return uint256_t(arg);
    return uint256_t(Float(arg.substr(0, last + 1)) * shift);
} };

template <>
struct Option<Address> {
static Address Parse(Args &args) {
    const auto arg(args());
    if (false);
    else if (arg == "tv0") {
        orc_assert_(*chain_ == 1, "tv0 is not on chain " << chain_);
        return "0x1fb31CcF378FDE2bFa8f1C5F35888162cE11b24f"; }
    else if (arg == "OTT") {
        orc_assert_(*chain_ == 1, "OTT is not on chain " << chain_);
        return "0xff9978B7b309021D39a76f52Be377F2B95D72394"; }
    else if (arg == "OXT") {
        orc_assert_(*chain_ == 1, "OXT is not on chain " << chain_);
        return "0x4575f41308EC1483f3d399aa9a2826d74Da13Deb"; }
    else return arg;
} };

template <>
struct Option<Locator> {
static Locator Parse(Args &args) {
    auto arg(args());
    if (false);
    else if (arg == "cloudflare")
        arg = "https://cloudflare-eth.com/";
    else if (arg == "ganache")
        arg = "http://127.0.0.1:7545/";
    return Locator::Parse(arg);
} };

template <>
struct Option<S<Executor>> {
static S<Executor> Parse(Args &args) {
    const auto arg(args());
    if (arg.size() == 64)
        return Make<SecretExecutor>(*chain_, Bless(arg));
    else
        return Make<UnlockedExecutor>(*chain_, arg);
} };

template <>
struct Option<Bytes> {
static Bytes Parse(Args &args) {
    auto code(args());
    if (!code.empty() && code[0] == '@')
        code = Load(code.substr(1));
    return Bless(code);
} };

template <typename ...Types_, size_t ...Indices_>
void Options(Args &args, std::tuple<Types_...> &options, std::index_sequence<Indices_...>) {
    ((std::get<Indices_>(options) = Option<Types_>::Parse(args)), ...);
}

template <typename ...Types_>
auto Options(Args &args) {
    std::tuple<Types_...> options;
    Options(args, options, std::index_sequence_for<Types_...>());
    orc_assert(!args);
    return options;
}

task<int> Main(int argc, const char *const argv[]) { try {
    Args args(argc - 1, argv + 1);

    #define ORC_PARAM(name, prefix, suffix) \
        else if (arg == "--" #name) { \
            static bool seen; \
            orc_assert(!seen); \
            seen = true; \
            prefix name##suffix = Option<decltype(prefix name##suffix)>::Parse(args); \
        }

    std::string executor;
    Flags flags;

    const auto command([&]() { for (;;) {
        const auto arg(args());
        orc_assert(!arg.empty());
        if (arg[0] != '-')
            return arg;
        if (false);
        ORC_PARAM(bid,,_)
        ORC_PARAM(executor,,)
        ORC_PARAM(insecure,flags.,_)
        ORC_PARAM(nonce,,_)
        ORC_PARAM(rpc,,_)
        ORC_PARAM(verbose,flags.,_)
    } }());

    const auto origin(Break<Local>());
    chain_ = co_await Chain::Create(Endpoint{origin, rpc_}, flags);

    if (executor.empty())
        executor_ = Make<MissingExecutor>(*chain_);
    else {
        Args args{std::move(executor)};
        executor_ = Option<decltype(executor_)>::Parse(args);
    }

    const auto block([&]() -> task<Block> {
        const auto height(co_await chain_->Height());
        const auto block(co_await chain_->Header(height));
        co_return block;
    });

    if (false) {

    } else if (command == "account") {
        const auto [address] = Options<Address>(args);
        const auto [account] = co_await chain_->Get(co_await block(), address, nullptr);
        std::cout << account.balance_ << std::endl;

    } else if (command == "accounts") {
        for (const auto &account : co_await (*chain_)("personal_listAccounts", {}))
            std::cout << Address(account.asString()) << std::endl;

    } else if (command == "address") {
        std::cout << Address(*executor_) << std::endl;

    } else if (command == "approve") {
        const auto [token, recipient, amount] = Options<Address, Address, uint256_t>(args);
        static Selector<bool, Address, uint256_t> approve("approve");
        const auto transaction(co_await executor_->Send(token, 0, approve(recipient, amount)));
        std::cout << transaction.hex() << std::endl;

    } else if (command == "balance") {
        const auto [token, address] = Options<Address, Address>(args);
        static Selector<uint256_t, Address> balanceOf("balanceOf");
        const auto balance(co_await balanceOf.Call(*chain_, "latest", token, 90000, address));
        std::cout << balance << std::endl;

    } else if (command == "code") {
        const auto [address] = Options<Address>(args);
        std::cout << (co_await chain_->Code(co_await block(), address)).hex() << std::endl;

    } else if (command == "deploy") {
        auto [amount, code, data] = Options<uint256_t, Bytes, Bytes>(args);
        const auto transaction(co_await executor_->Send(std::nullopt, amount, Tie(code, data)));
        std::cout << transaction.hex() << std::endl;

    } else if (command == "derive") {
        const auto [secret] = Options<Bytes32>(args);
        std::cout << Commonize(secret).hex() << std::endl;

    } else if (command == "factory") {
        Options<>(args);
        if (bid_ == 0)
            bid_ = uint256_t(100 * Ten9);
        Record record(*chain_, 0, bid_, 247000, std::nullopt, 0, Bless("0x608060405234801561001057600080fd5b50610134806100206000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c80634af63f0214602d575b600080fd5b60cf60048036036040811015604157600080fd5b810190602081018135640100000000811115605b57600080fd5b820183602082011115606c57600080fd5b80359060200191846001830284011164010000000083111715608d57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929550509135925060eb915050565b604080516001600160a01b039092168252519081900360200190f35b6000818351602085016000f5939250505056fea26469706673582212206b44f8a82cb6b156bfcc3dc6aadd6df4eefd204bc928a4397fd15dacf6d5320564736f6c63430006020033"), 27, 0x247000, 0x2470);
        std::cout << record.from_ << std::endl;

    } else if (command == "generate") {
        Options<>(args);
        const auto secret(Random<32>());
        std::cout << secret.hex().substr(2) << std::endl;

    } else if (command == "hash") {
        auto [data] = Options<Bytes>(args);
        std::cout << Hash(data).hex() << std::endl;

    } else if (command == "height") {
        Options<>(args);
        std::cout << co_await chain_->Height() << std::endl;

    } else if (command == "hex") {
        Options<>(args);
        std::cout << "0x";
        std::cout << std::setbase(16) << std::setfill('0');
        for (;;) {
#ifdef _WIN32
            const auto byte(getchar());
#else
            const auto byte(getchar_unlocked());
#endif
            if (byte == EOF)
                break;
            std::cout << std::setw(2) << byte;
        }
        std::cout << std::endl;

    } else if (command == "nonce") {
        const auto [address] = Options<Address>(args);
        const auto [account] = co_await chain_->Get(co_await block(), address, nullptr);
        std::cout << account.nonce_ << std::endl;

    } else if (command == "receipt") {
        const auto [transaction] = Options<Bytes32>(args);
        for (;;)
            if (const auto receipt{co_await (*chain_)[transaction]}) {
                std::cout << receipt->contract_ << std::endl;
                break;
            } else co_await Sleep(1000);

    } else if (command == "send") {
        const auto [recipient, amount, data] = Options<Address, uint256_t, Bytes>(args);
        const auto transaction(co_await executor_->Send(recipient, amount, data));
        std::cout << transaction.hex() << std::endl;

#if 0
    } else if (command == "singleton") {
        auto [code, salt] = Options<Bytes, Bytes32>(args);
        static Selector<Address, Bytes, Bytes32> deploy("deploy");
        const auto transaction(co_await executor_->Send(factory, 0, deploy(code, salt)));
        std::cout << transaction.hex() << std::endl;
#endif

    } else if (command == "submit") {
        const auto [raw] = Options<Bytes>(args);
        const auto transaction(co_await chain_->Send("eth_sendRawTransaction", {raw}));
        std::cout << transaction.hex() << std::endl;

    } else if (command == "transfer") {
        const auto [token, recipient, amount, data] = Options<Address, Address, uint256_t, Bytes>(args);
        static Selector<bool, Address, uint256_t> transfer("transfer");
        static Selector<void, Address, uint256_t, Bytes> transferAndCall("transferAndCall");
        const auto transaction(co_await executor_->Send(token, 0, data.size() == 0 ?
            transfer(recipient, amount) : transferAndCall(recipient, amount, data)));
        std::cout << transaction.hex() << std::endl;

    } else if (command == "transferv") {
        orc_assert(nonce_);
        const auto [token, sender] = Options<Address, Address>(args);

        typedef std::tuple<Address, uint256_t> Send;
        std::vector<Send> sends;
        uint256_t total(0);

        const auto csv(Load(std::to_string(uint64_t(*nonce_)) + ".csv"));
        for (const auto &line : Split(csv, {'\n'})) {
            if (line.size() == 0 || line[0] == '#')
                continue;
            const auto comma(Find(line, {','}));
            orc_assert(comma);
            const auto [recipient, amount] = Split(line, *comma);
            const auto &send(sends.emplace_back(std::string(recipient), std::string(amount)));
            std::cout << "transfer " << token << " " << std::get<0>(send) << " " << std::get<1>(send) << std::endl;
            total += std::get<1>(send);
        }

        std::cout << "total = " << total << std::endl;

        static Selector<void, Address, uint256_t, std::vector<Send>> transferv("transferv");
        const auto transaction(co_await executor_->Send({.nonce=nonce_}, sender, 0, transferv(token, total, sends)));
        std::cout << transaction.hex() << std::endl;

    } else orc_assert_(false, "unknown command " << command);

    co_return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << std::endl;
    co_return 1;
} }

}

int main(int argc, char* argv[]) {
    _exit(orc::Wait(orc::Main(argc, argv)));
}
