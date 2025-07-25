// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {DataStreamsStructs} from "../vendor/DataStreamsStructs.sol";

contract FeedDataFixture is DataStreamsStructs {
    bytes32 internal constant FEED_SIGNED = bytes32(uint256(0x01));

    uint8 internal constant UNSUPPORTED_REPORT_VERSION = 60;

    function generateSimpleReportData(bytes32 feedId, bool signed) public view returns (bytes memory unverifiedReport) {
        uint32 validFrom = uint32(block.timestamp - 3600); // Valid from 1 hour ago
        uint32 observationsTimestamp = validFrom + 1;
        uint32 expiresAt = uint32(block.timestamp + 3600); // Expires in 1 hour

        int192 price = 3000 * 10 ** 18;

        return generateReportData(feedId, validFrom, observationsTimestamp, expiresAt, price, signed);
    }

    function generateReportData(
        bytes32 feedId,
        uint32 validFromTimestamp,
        uint32 observationsTimestamp,
        uint32 expiresAt,
        int192 price,
        bool signed
    ) public pure returns (bytes memory unverifiedReport) {
        bytes32[3] memory metadata;

        if (signed) {
            metadata[0] = FEED_SIGNED;
        }

        // The report version is stored in the highest two bytes of the feedId
        uint16 reportVersion = (uint16(uint8(feedId[0])) << 8) | uint16(uint8(feedId[1]));

        bytes memory encodedReport;

        if (reportVersion == 4) {
            encodedReport = abi.encode(
                ReportV4({
                    feedId: feedId,
                    validFromTimestamp: validFromTimestamp,
                    observationsTimestamp: observationsTimestamp,
                    nativeFee: 0,
                    linkFee: 0,
                    expiresAt: expiresAt,
                    price: price,
                    marketStatus: 1
                })
            );
        } else if (reportVersion == 3) {
            encodedReport = abi.encode(
                ReportV3({
                    feedId: feedId,
                    validFromTimestamp: validFromTimestamp,
                    observationsTimestamp: observationsTimestamp,
                    nativeFee: 0,
                    linkFee: 0,
                    expiresAt: expiresAt,
                    price: price,
                    bid: price,
                    ask: price
                })
            );
        } else if (reportVersion == 2) {
            encodedReport = abi.encode(
                ReportV2({
                    feedId: feedId,
                    validFromTimestamp: validFromTimestamp,
                    observationsTimestamp: observationsTimestamp,
                    nativeFee: 0,
                    linkFee: 0,
                    expiresAt: expiresAt,
                    price: price
                })
            );
        } else if (reportVersion == UNSUPPORTED_REPORT_VERSION) {
            encodedReport = abi.encode(feedId);
        } else {
            revert("Unsupported report version");
        }

        unverifiedReport = abi.encode(metadata, encodedReport);
    }
}
