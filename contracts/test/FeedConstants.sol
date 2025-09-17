// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

contract FeedConstants {
    struct FeedDescriptor {
        bytes32 feedId;
        uint8 decimals;
        string description;
    }

    uint32 internal constant ROUND_ID_FIRST = 1;
    uint80 internal constant ROUND_ID_TOO_LARGE = 2 ** 32;

    FeedDescriptor internal ETH_USD_V2 =
        FeedDescriptor({
            // Fake feedId to represent a V2 feed
            feedId: 0x000262205e10b3a147d02792eccee483dca6c7b44ecce7012cb8c6e0b68b3ae9,
            decimals: 18,
            description: "ETH/USD"
        });

    FeedDescriptor internal ETH_USD_V3 =
        FeedDescriptor({
            feedId: 0x000362205e10b3a147d02792eccee483dca6c7b44ecce7012cb8c6e0b68b3ae9,
            decimals: 18,
            description: "ETH/USD"
        });

    FeedDescriptor internal ETH_USD_V4 =
        FeedDescriptor({
            // Fake feedId to represent a V4 feed
            feedId: 0x000462205e10b3a147d02792eccee483dca6c7b44ecce7012cb8c6e0b68b3ae9,
            decimals: 18,
            description: "ETH/USD"
        });

    FeedDescriptor internal ETH_USD_V60 =
        FeedDescriptor({
            // Fake feedId to represent a V60 feed
            feedId: 0x003C62205e10b3a147d02792eccee483dca6c7b44ecce7012cb8c6e0b68b3ae9,
            decimals: 18,
            description: "ETH/USD"
        });

    FeedDescriptor internal BTC_USD_V2 =
        FeedDescriptor({
            // Fake feedId to represent a V2 feed
            feedId: 0x00029d9e45394f473ab1f050a1b963e6b05351e52d71e507509ada0c95ed75b8,
            decimals: 18,
            description: "BTC/USD"
        });

    FeedDescriptor internal BTC_USD_V3 =
        FeedDescriptor({
            feedId: 0x00039d9e45394f473ab1f050a1b963e6b05351e52d71e507509ada0c95ed75b8,
            decimals: 18,
            description: "BTC/USD"
        });

    FeedDescriptor internal BTC_USD_V4 =
        FeedDescriptor({
            // Fake feedId to represent a V4 feed
            feedId: 0x00049d9e45394f473ab1f050a1b963e6b05351e52d71e507509ada0c95ed75b8,
            decimals: 18,
            description: "BTC/USD"
        });

    FeedDescriptor internal FAKE_USD_8DEC_V3 =
        FeedDescriptor({feedId: bytes32(uint256(0x01)), decimals: 8, description: "FAKE/USD"});

    FeedDescriptor internal USR_USD_V7 =
        FeedDescriptor({
            feedId: 0x0007c505034a2b88e6fe4829ae1b559911856a28d0643c6af36c7d7a6de7add6,
            decimals: 10,
            description: "USR/USD"
        });

    FeedDescriptor internal AAPL_USD_V8 =
        FeedDescriptor({
            feedId: 0x0008e64e9538dea4c50f9a8203d2c8993b6f3756da73cabafbb204637310c450,
            decimals: 18,
            description: "AAPL/USD"
        });
}
