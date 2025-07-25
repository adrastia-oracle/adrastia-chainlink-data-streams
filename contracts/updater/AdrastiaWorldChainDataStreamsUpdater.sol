// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

import {AdrastiaDataStreamsUpdater} from "./AdrastiaDataStreamsUpdater.sol";

interface IWorldChainFeed {
    function FEED_ID() external view returns (bytes32);

    function updatePriceData(
        bytes memory verifyReportRequest,
        bytes memory parameterPayload
    ) external returns (bytes memory);
}

/**
 * @title AdrastiaWorldChainDataStreamsUpdater
 * @author Tyler Loewen, TRILEZ SOFTWARE INC. dba. Adrastia
 * @notice This contract is an implementation of the AdrastiaDataStreamsUpdater for World Chain feeds.
 *
 * These feeds handle verification themselves, so this contract changes performUpkeep to call the feed contract
 * directly with the unverified report. The feed contract will then verify the report and update the price data.
 *
 * This contract assumes that there are no LINK token fees associated with the verification of the report. The
 * perforkUpkeep function does not implement access control because it's unable to spend LINK tokens. The
 * approveVerifierFeeSpend function is a no-op.
 */
contract AdrastiaWorldChainDataStreamsUpdater is AdrastiaDataStreamsUpdater {
    using EnumerableMap for EnumerableMap.Bytes32ToAddressMap;

    constructor(
        address verifierProxy,
        address initialAdmin
    ) AdrastiaDataStreamsUpdater(verifierProxy, initialAdmin, initialAdmin) {}

    function performUpkeep(bytes calldata performData) external payable virtual override {
        bytes[] memory unverifiedReports = abi.decode(performData, (bytes[]));

        bytes memory parameterPayload = abi.encode(address(0));

        uint256 successCount = 0;

        for (uint256 i = 0; i < unverifiedReports.length; ++i) {
            // Decode unverified report to extract report data
            (, bytes memory reportData) = abi.decode(unverifiedReports[i], (bytes32[3], bytes));

            // Extract extract the feedId from the reportData, which is always stored in the first 32 bytes of the
            // report data.
            // Extract the observationsTimestamp for the report. Used for short-circuiting the update if old.
            (bytes32 feedId, , uint32 feedObservationsTimestamp) = abi.decode(reportData, (bytes32, uint32, uint32));

            // Get the data stream address
            (bool feedExists_, address targetFeed) = _feedTargets.tryGet(feedId);
            if (!feedExists_) {
                // The updater should never try to update a feed that is not registered
                revert FeedNotRegistered(feedId);
            }

            // Get the contract latest report timestamp
            (, uint256 storedTimestamp) = readUnderlyingFeed(feedId);
            if (storedTimestamp >= feedObservationsTimestamp) {
                // The provided report is old, skip it
                emit FeedUpdateSkipped(feedId, targetFeed, storedTimestamp, feedObservationsTimestamp, block.timestamp);

                continue;
            }

            // Pass the unverified report to the feed contract for verification and update
            (bool success, bytes memory data) = targetFeed.call(
                abi.encodeWithSelector(IWorldChainFeed.updatePriceData.selector, unverifiedReports[i], parameterPayload)
            );
            if (success) {
                // Emit an event for the successful update
                emit FeedUpdatePerformed(feedId, targetFeed, block.timestamp);

                ++successCount;
            } else {
                // Log the error
                emit FeedUpdateFailed(feedId, targetFeed, data, block.timestamp);
            }
        }

        if (successCount == 0) {
            revert NoFeedsUpdated();
        }
    }

    function approveVerifierFeeSpend() public virtual override {
        // NO-OP
    }

    function _getIdFromFeed(address feed) internal view virtual override returns (bytes32) {
        return IWorldChainFeed(feed).FEED_ID();
    }
}
