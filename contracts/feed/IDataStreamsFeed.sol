// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IVerifierProxy} from "../vendor/IVerifierProxy.sol";

/**
 * @title IDataStreamsFeed
 * @author TRILEZ SOFTWARE INC. dba. Adrastia
 * @notice An interface for Chainlink Data Streams feeds. This interface defines the functions that allow for updating
 * reports using either verified report data (from a trusted updater) or unverified report data (which will be
 * verified before updating the feed).
 */
interface IDataStreamsFeed {
    /**
     * @notice Gets the address of the Chainlink Data Streams verifier proxy that's used to verify report data.
     *
     * @return The address of the verifier proxy contract.
     */
    function verifierProxy() external view returns (IVerifierProxy);

    /**
     * @notice Gets the Chainlink Data Streams feed ID.
     *
     * @return The bytes32 ID of the feed.
     */
    function feedId() external view returns (bytes32);

    /**
     * @notice Updates the latest report data using verified report data. Great trust is required in anyone with the
     * ability to call this function, as it allows them to update the feed without verification.
     * @dev This function is intended to be called by a contract that verifies report data before passing it to this
     * function, such as an AdrastiaDataStreamsUpdater contract.
     *
     * @param reportVersion The version of the report data.
     * @param verifiedReportData The verified report data, to be from the Chainlink Data Streams verifier proxy.
     */
    function updateReport(uint16 reportVersion, bytes calldata verifiedReportData) external;

    /**
     * @notice Verifies the provided unverified report data and updates the feed with the verified data.
     *
     * @param unverifiedReportData The unverified report data that needs to be verified.
     * @param parameterPayload Data passed to the verifier proxy for verification. Typically, this will be the address
     * of the ERC20 token used to pay for fees.
     */
    function verifyAndUpdateReport(bytes calldata unverifiedReportData, bytes calldata parameterPayload) external;
}
