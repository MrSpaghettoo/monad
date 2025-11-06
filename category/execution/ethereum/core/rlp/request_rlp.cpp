// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <category/core/byte_string.hpp>
#include <category/core/likely.h>
#include <category/core/result.hpp>
#include <category/core/rlp/config.hpp>
#include <category/execution/ethereum/core/rlp/bytes_rlp.hpp>
#include <category/execution/ethereum/core/rlp/int_rlp.hpp>
#include <category/execution/ethereum/core/request.hpp>
#include <category/execution/ethereum/rlp/decode.hpp>
#include <category/execution/ethereum/rlp/decode_error.hpp>
#include <category/execution/ethereum/rlp/encode2.hpp>

#include <boost/outcome/try.hpp>

#include <cstdint>
#include <utility>
#include <vector>

MONAD_RLP_NAMESPACE_BEGIN

byte_string encode_request(Request const &request)
{
    return encode_list2(
        encode_unsigned(request.request_type),
        encode_string2(request.request_data));
}

Result<Request> decode_request(byte_string_view &enc)
{
    Request request;
    if (enc.size() == 0) {
        return request;
    }
    BOOST_OUTCOME_TRY(auto payload, parse_list_metadata(enc));
    BOOST_OUTCOME_TRY(
        request.request_type, decode_unsigned<uint8_t>(payload));
    BOOST_OUTCOME_TRY(request.request_data, decode_string(payload));

    if (MONAD_UNLIKELY(!payload.empty())) {
        return DecodeError::InputTooLong;
    }

    return request;
}

Result<std::vector<Request>> decode_request_list(byte_string_view &enc)
{
    std::vector<Request> request_list;
    BOOST_OUTCOME_TRY(auto payload, parse_list_metadata(enc));
    request_list.reserve(payload.size() / 32); // rough estimate

    while (payload.size() > 0) {
        BOOST_OUTCOME_TRY(auto request, decode_request(payload));
        request_list.emplace_back(std::move(request));
    }

    if (MONAD_UNLIKELY(!payload.empty())) {
        return DecodeError::InputTooLong;
    }

    return request_list;
}

MONAD_RLP_NAMESPACE_END

