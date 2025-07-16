// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IDataStreamsPreUpdateHook
 * @author Tyler Loewen, TRILEZ SOFTWARE INC. dba. Adrastia
 * @notice An interface for a hook that is called immediately before a Chainlink Data Streams feed report is updated.
 * This interface allows for custom logic to be executed before a report is updated, such as logging, triggering
 * events, or interacting with other contracts.
 */
interface IDataStreamsPreUpdateHook {
    /**
     * @notice Called immediately before a report is updated in the Chainlink Data Streams feed.
     *
     * @param feedId The bytes32 ID of the feed that was updated.
     * @param roundId The round ID of the report that was updated.
     * @param price The price observed in the report.
     * @param observationTimestamp The timestamp when the observation was made.
     * @param expiresAt The timestamp when the report expires.
     * @param updatedAt The timestamp when the report was last updated.
     */
    function onPreReportUpdate(
        bytes32 feedId,
        uint32 roundId,
        int192 price,
        uint32 observationTimestamp,
        uint32 expiresAt,
        uint32 updatedAt
    ) external;
}
