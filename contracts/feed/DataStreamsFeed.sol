// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {AggregatorV2V3Interface} from "../vendor/AggregatorV2V3Interface.sol";
import {DataStreamsStructs} from "../vendor/DataStreamsStructs.sol";
import {AdrastiaDataStreamsCommon} from "../common/AdrastiaDataStreamsCommon.sol";
import {IDataStreamsFeed} from "./IDataStreamsFeed.sol";
import {IVerifierProxy} from "../vendor/IVerifierProxy.sol";
import {IFeeManager} from "../vendor/IFeeManager.sol";
import {Roles} from "../common/Roles.sol";

/**
 * @title DataStreamsFeed
 * @author Tyler Loewen, TRILEZ SOFTWARE INC. dba. Adrastia
 * @notice The Data Streams contract is responsible for storing and serving the latest report data from Chainlink
 * Data Streams feeds.
 *
 * Access is controlled using OpenZeppelin's AccessControlEnumerable, allowing for fine-grained permissions.
 * The roles are setup as follows:
 * - ADMIN: Can manage the role and sub-roles.
 *   - REPORT_VERIFIER: Can call `updateReport` to update the latest report data. Ideally, accounts with this role
 *     should be the Adrastia Data Streams Updater contract that verifies reports in bulk. This role is not required
 *     when using the `verifyAndUpdateReport` function, as that function will verify the report before updating it.
 *
 * This contract implements Chainlink's AggregatorV2V3Interface, allowing for easy integration with existing protocols.
 * Round IDs start at 1 and increment with each report update, allowing for over a hundred years of unique round IDs.
 *
 * The functions `latestAnswer` and `latestRoundData` will revert if the latest report is expired or if there is no
 * report. The functions `latestTimestamp` and `latestRound` do not revert if the latest report is expired to allow
 * for introspection of the latest report data, even if it is expired. This is useful for anyone querying past rounds
 * using `latestRound`. Functions that return report data for specific round IDs do not check for expiration, as they
 * are expected to be used for historical data retrieval.
 */
contract DataStreamsFeed is
    IDataStreamsFeed,
    AggregatorV2V3Interface,
    AdrastiaDataStreamsCommon,
    DataStreamsStructs,
    AccessControlEnumerable
{
    /**
     * @notice The report data structure. This is a truncated version of the full report data to only occupy two storage
     * slots.
     */
    struct TruncatedReport {
        // SLOT 1
        /**
         * @notice The price of the report. This is a signed integer, as prices can be negative.
         */
        int192 price;
        /**
         * @notice The timestamp of the report (observation time), in seconds since the Unix epoch.
         */
        uint32 observationTimestamp;
        /**
         * @notice The timestamp at which the report expires, in seconds since the Unix epoch.
         */
        uint32 expiresAt;
        // SLOT 2
        /**
         * @notice The timestamp at which the report was stored, in seconds since the Unix epoch.
         */
        uint32 storageTimestamp;
        /**
         * @notice The round ID of the report. Starts at 1 and increments with each report update.
         *
         * @dev Only 1 report can be comitted every second, so this allows for over a hundred years of unique round IDs.
         */
        uint32 roundId;
    }

    /**
     * @notice The Chainlink verifier proxy contract.
     */
    IVerifierProxy public immutable override verifierProxy;

    /**
     * @notice The ID of the feed. This is the same as the feedId in the report.
     */
    bytes32 public immutable override feedId;

    /**
     * @notice The number of decimals used in the feed. This is the same as the decimals used in the report.
     */
    uint8 public immutable override decimals;

    /**
     * @notice The description of the feed.
     */
    string public override description;

    /**
     * @notice The latest report data.
     */
    TruncatedReport internal latestReport;

    /**
     * @notice A mapping of round IDs to historical reports.
     */
    mapping(uint32 => TruncatedReport) internal historicalReports;

    /**
     * @notice An event emitted when the latest report is updated.
     *
     * @param feedId The ID of the feed. This is the same as the feedId in the report.
     * @param updater The address of the account updating the report.
     * @param roundId The round ID of the report. Starts at 1 and increments with each report update.
     * @param price The price of the report. This is a signed integer, as prices can be negative.
     * @param validFromTimestamp The timestamp at which the report becomes valid, in seconds since the Unix epoch.
     * @param observationsTimestamp The timestamp of the report, in seconds since the Unix epoch.
     * @param expiresAt The timestamp at which the report expires, in seconds since the Unix epoch.
     * @param timestamp The block timestamp at which the report was updated, in seconds since the Unix epoch.
     */
    event ReportUpdated(
        bytes32 indexed feedId,
        address indexed updater,
        uint32 roundId,
        int192 price,
        uint32 validFromTimestamp,
        uint32 observationsTimestamp,
        uint32 expiresAt,
        uint32 timestamp
    );

    /**
     * @notice An errror thrown passing invalid constructor arguments.
     */
    error InvalidConstructorArguments();

    /**
     * @notice An error thrown when the feed has never received a report, and one is expected.
     */
    error MissingReport();

    /**
     * @notice An error thrown when the report is expired.
     * @param expiresAt The timestamp at which the report expired.
     * @param currentTimestamp The current timestamp.
     */
    error ReportIsExpired(uint32 expiresAt, uint32 currentTimestamp);

    /**
     * @notice An error thrown when, upon updating the report, the report's feed ID does not match this contract's feed
     * ID.
     * @param expectedFeedId This contract's feed ID.
     * @param providedFeedId The feed ID provided in the report.
     */
    error FeedMismatch(bytes32 expectedFeedId, bytes32 providedFeedId);

    /**
     * @notice An error thrown when the report is not yet valid.
     * @param validFromTimestamp The timestamp at which the report becomes valid.
     * @param currentTimestamp The current timestamp.
     */
    error ReportIsNotValidYet(uint32 validFromTimestamp, uint32 currentTimestamp);

    /**
     * @notice An error thrown when the report's observation timestamp is in the future.
     * @param observationTimestamp The timestamp of the report's observation.
     * @param currentTimestamp The current timestamp.
     */
    error ReportObservationTimeInFuture(uint32 observationTimestamp, uint32 currentTimestamp);

    /**
     * @notice An error thrown when, upon updating the report, the provided report is stale, compared to the latest
     * report.
     * @param latestTimestamp The timestamp (observation time) of the latest report.
     * @param providedTimestamp The timestamp (observation time) of the provided report.
     */
    error StaleReport(uint32 latestTimestamp, uint32 providedTimestamp);

    /**
     * @notice An error thrown when, upon updating the report, the report has a timestamp (observation time) of 0.
     */
    error InvalidReport();

    /**
     * @notice An error thrown when, upon updating the report, the report is a duplicate of the latest report.
     */
    error DuplicateReport();

    /**
     * @notice Constructs a new DataStreamsFeed contract, granting the ADMIN role to the creator of the contract.
     *
     * @param verifierProxy_ The address of the Chainlink verifier proxy contract.
     * @param _feedId The ID of the feed. This is the same as the feedId in the report.
     * @param _decimals The number of decimals used in the feed. This is the same as the decimals used in the report.
     * @param _description The description of the feed.
     */
    constructor(address verifierProxy_, bytes32 _feedId, uint8 _decimals, string memory _description) {
        if (verifierProxy_ == address(0) || _feedId == bytes32(0)) {
            // These are definitely invalid arguments
            revert InvalidConstructorArguments();
        }

        verifierProxy = IVerifierProxy(verifierProxy_);
        feedId = _feedId;
        decimals = _decimals;
        description = _description;

        latestReport = TruncatedReport(0, 0, 0, 0, 0);

        _initializeRoles(msg.sender);
    }

    /**
     * @notice Returns the version of the contract.
     *
     * @return The version of the contract.
     */
    function version() external pure override returns (uint256) {
        return 1;
    }

    /**
     * @notice Returns the latest price, if available and not expired.
     * @dev This function will revert if the latest report is expired or if there is no report.
     *
     * @return The latest report price.
     */
    function latestAnswer() external view override returns (int256) {
        TruncatedReport memory report = latestReport;
        if (report.expiresAt <= block.timestamp) {
            if (report.observationTimestamp == 0) {
                revert MissingReport();
            }

            revert ReportIsExpired(report.expiresAt, uint32(block.timestamp));
        }

        return report.price;
    }

    /**
     * @notice Returns the latest timestamp, if available.
     * @dev This function will revert if there's no report.
     *
     * @return The latest report timestamp (observation time).
     */
    function latestTimestamp() external view override returns (uint256) {
        TruncatedReport memory report = latestReport;
        if (report.observationTimestamp == 0) {
            revert MissingReport();
        }

        return report.observationTimestamp;
    }

    /**
     * @notice Returns the latest round ID, if available.
     * @dev This function will revert if there's no report.
     *
     * @return The latest report round ID.
     */
    function latestRound() external view override returns (uint256) {
        TruncatedReport memory report = latestReport;
        if (report.observationTimestamp == 0) {
            revert MissingReport();
        }

        return report.roundId;
    }

    /**
     * @notice Returns the report price for the specified round ID.
     * @dev This function will revert if there is no report for the specified round ID.
     *
     * @param roundId The round ID to check. Round IDs start at 1 and increment with each report update.
     *
     * @return The price observed in the report.
     */
    function getAnswer(uint256 roundId) external view override returns (int256) {
        if (roundId > type(uint32).max) {
            // Round ID is too large to be valid
            revert MissingReport();
        }

        TruncatedReport memory report = historicalReports[uint32(roundId)];
        if (report.observationTimestamp == 0) {
            revert MissingReport();
        }

        return report.price;
    }

    /**
     * @notice Returns the timestamp (observation time) of the report for the specified round ID.
     * @dev This function will revert if there is no report for the specified round ID.
     *
     * @param roundId The round ID to check. Round IDs start at 1 and increment with each report update.
     *
     * @return The timestamp of the report (observation time), in seconds since the Unix epoch.
     */
    function getTimestamp(uint256 roundId) external view override returns (uint256) {
        if (roundId > type(uint32).max) {
            // Round ID is too large to be valid
            revert MissingReport();
        }

        TruncatedReport memory report = historicalReports[uint32(roundId)];
        if (report.observationTimestamp == 0) {
            revert MissingReport();
        }

        return report.observationTimestamp;
    }

    /**
     * @notice Returns the report data for the specified round ID, if any.
     * @dev This function will revert if there is no report for the specified round ID.
     *
     * @param _roundId The round ID to check. Round IDs start at 1 and increment with each report update.
     *
     * @return roundId The round ID of the report.
     * @return answer The price observed in the report.
     * @return startedAt The timestamp of the report.
     * @return updatedAt The timestamp from when the report was stored.
     * @return answeredInRound The round ID of the report.
     */
    function getRoundData(
        uint80 _roundId
    )
        external
        view
        override
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        if (_roundId > type(uint32).max) {
            // Round ID is too large to be valid
            revert MissingReport();
        }

        TruncatedReport memory report = historicalReports[uint32(_roundId)];
        if (report.observationTimestamp == 0) {
            revert MissingReport();
        }

        return (
            report.roundId, // roundId
            report.price, // answer
            report.observationTimestamp, // startedAt
            report.storageTimestamp, // updatedAt
            report.roundId // answeredInRound
        );
    }

    /**
     * @notice Returns the latest report data, if available and not expired.
     * @dev This function will revert if the latest report is expired or if there is no report.
     *
     * @return roundId The round ID of the report.
     * @return answer The price observed in the report.
     * @return startedAt The timestamp of the report.
     * @return updatedAt The timestamp from when the report was stored.
     * @return answeredInRound The round ID of the report.
     */
    function latestRoundData()
        external
        view
        override
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        TruncatedReport memory report = latestReport;
        if (report.expiresAt <= block.timestamp) {
            if (report.observationTimestamp == 0) {
                revert MissingReport();
            }

            revert ReportIsExpired(report.expiresAt, uint32(block.timestamp));
        }

        return (
            report.roundId, // roundId
            report.price, // answer
            report.observationTimestamp, // startedAt
            report.storageTimestamp, // updatedAt
            report.roundId // answeredInRound
        );
    }

    /**
     * @notice Updates the latest report data. Only callable by addresses with the REPORT_VERIFIER role.
     *
     * WARNING: Verification is to be performed by the caller. This function does not perform any verification other
     * than basic data integrity checks.
     *
     * @param reportVersion The version of the report data. Must be either 2, 3, or 4.
     * @param verifiedReportData The verified report data, to be from the verifier proxy.
     */
    function updateReport(
        uint16 reportVersion,
        bytes calldata verifiedReportData
    ) external virtual override onlyRole(Roles.REPORT_VERIFIER) {
        _updateReport(reportVersion, verifiedReportData);
    }

    /// @inheritdoc IDataStreamsFeed
    function verifyAndUpdateReport(
        bytes calldata unverifiedReportData,
        bytes calldata parameterPayload
    ) external virtual override {
        // Decode unverified report to extract report data
        (, bytes memory reportData) = abi.decode(unverifiedReportData, (bytes32[3], bytes));

        // Extract report version from reportData
        uint16 reportVersion = (uint16(uint8(reportData[0])) << 8) | uint16(uint8(reportData[1]));
        if (reportVersion < 2 || reportVersion > 4) {
            // Invalid report version. Revert early to save on gas (skip verification).
            revert InvalidReportVersion(reportVersion);
        }

        // Handle fee approval (if any)
        _handleFeeApproval();

        // Verify the report
        bytes memory verifiedReportData = verifierProxy.verify(unverifiedReportData, parameterPayload);

        // Parse, validate, and store the report
        _updateReport(reportVersion, verifiedReportData);
    }

    /**
     * @notice Withdraws ERC20 tokens from the contract.
     *
     * @param token The token address.
     * @param to The recipient address.
     * @param amount The amount to withdraw.
     */
    function withdrawErc20(address token, address to, uint256 amount) external virtual onlyRole(Roles.ADMIN) {
        SafeERC20.safeTransfer(IERC20(token), to, amount);
    }

    /**
     * @notice The hash of the ADMIN role.
     *
     * @return The hash of the ADMIN role.
     */
    function ADMIN() external pure returns (bytes32) {
        return Roles.ADMIN;
    }

    /**
     * @notice The hash of the REPORT_VERIFIER role.
     *
     * @return The hash of the REPORT_VERIFIER role.
     */
    function REPORT_VERIFIER() external pure returns (bytes32) {
        return Roles.REPORT_VERIFIER;
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceID) public view virtual override returns (bool) {
        return
            interfaceID == type(IDataStreamsFeed).interfaceId ||
            interfaceID == type(AggregatorV2V3Interface).interfaceId ||
            AccessControlEnumerable.supportsInterface(interfaceID);
    }

    function _handleFeeApproval() internal virtual {
        // Retrieve fee manager and reward manager
        IFeeManager feeManager = IFeeManager(address(verifierProxy.s_feeManager()));
        if (address(feeManager) == address(0)) {
            // No fee manager. Fees are disabled.
            return;
        }

        // Set the fee token address (LINK in this case)
        IERC20 feeToken = IERC20(feeManager.i_linkAddress());
        if (address(feeToken) == address(0)) {
            // No fee token. Fees are disabled.
            return;
        }

        address rewardManager = feeManager.i_rewardManager();
        if (rewardManager == address(0)) {
            // No reward manager. Fees are disabled.
            return;
        }

        uint256 allowance = feeToken.allowance(address(this), rewardManager);
        if (allowance == 0) {
            feeToken.approve(rewardManager, type(uint256).max);
        }
    }

    /**
     * @notice Updates the latest report data.
     *
     * @param reportVersion The version of the report data. Must be either 2, 3, or 4.
     * @param verifiedReportData The verified report data, generated by the verifier proxy.
     */
    function _updateReport(uint16 reportVersion, bytes memory verifiedReportData) internal virtual {
        bytes32 reportFeedId;
        int192 reportPrice;
        uint32 reportValidFromTimestamp;
        uint32 reportTimestamp;
        uint32 reportExpiresAt;

        if (reportVersion == 2) {
            // v2 report schema
            ReportV2 memory verifiedReport = abi.decode(verifiedReportData, (ReportV2));

            // Extract the details
            reportFeedId = verifiedReport.feedId;
            reportPrice = verifiedReport.price;
            reportValidFromTimestamp = verifiedReport.validFromTimestamp;
            reportTimestamp = verifiedReport.observationsTimestamp;
            reportExpiresAt = verifiedReport.expiresAt;
        } else if (reportVersion == 3) {
            // v3 report schema
            ReportV3 memory verifiedReport = abi.decode(verifiedReportData, (ReportV3));

            // Extract the details
            reportFeedId = verifiedReport.feedId;
            reportPrice = verifiedReport.price;
            reportValidFromTimestamp = verifiedReport.validFromTimestamp;
            reportTimestamp = verifiedReport.observationsTimestamp;
            reportExpiresAt = verifiedReport.expiresAt;
        } else if (reportVersion == 4) {
            // v4 report schema
            ReportV4 memory verifiedReport = abi.decode(verifiedReportData, (ReportV4));

            // Extract the details
            reportFeedId = verifiedReport.feedId;
            reportPrice = verifiedReport.price;
            reportValidFromTimestamp = verifiedReport.validFromTimestamp;
            reportTimestamp = verifiedReport.observationsTimestamp;
            reportExpiresAt = verifiedReport.expiresAt;
        } else {
            revert InvalidReportVersion(reportVersion);
        }

        if (reportFeedId != feedId) {
            revert FeedMismatch(feedId, reportFeedId);
        }

        if (block.timestamp >= reportExpiresAt) {
            revert ReportIsExpired(reportExpiresAt, uint32(block.timestamp));
        }

        if (block.timestamp < reportValidFromTimestamp) {
            // The report is not yet valid
            revert ReportIsNotValidYet(reportValidFromTimestamp, uint32(block.timestamp));
        }

        if (block.timestamp < reportTimestamp) {
            // The report timestamp is in the future
            revert ReportObservationTimeInFuture(reportTimestamp, uint32(block.timestamp));
        }

        TruncatedReport memory lastReport = latestReport;

        if (
            reportPrice == lastReport.price &&
            reportTimestamp == lastReport.observationTimestamp &&
            reportExpiresAt == lastReport.expiresAt
        ) {
            // The report is a duplicate
            revert DuplicateReport();
        }

        if (reportTimestamp <= lastReport.observationTimestamp) {
            // The report is stale
            revert StaleReport(lastReport.observationTimestamp, reportTimestamp);
        }

        if (reportTimestamp == 0) {
            // The report is invalid
            revert InvalidReport();
        }

        uint32 newRoundId = lastReport.roundId + 1;

        historicalReports[newRoundId] = latestReport = TruncatedReport({
            price: reportPrice,
            observationTimestamp: reportTimestamp,
            expiresAt: reportExpiresAt,
            storageTimestamp: uint32(block.timestamp),
            roundId: newRoundId
        });

        emit AnswerUpdated(reportPrice, reportTimestamp, block.timestamp);

        emit ReportUpdated(
            reportFeedId,
            msg.sender,
            newRoundId,
            reportPrice,
            reportValidFromTimestamp,
            reportTimestamp,
            reportExpiresAt,
            uint32(block.timestamp)
        );
    }

    function _initializeRoles(address initialAdmin) internal virtual {
        // ADMIN self administer their role
        _setRoleAdmin(Roles.ADMIN, Roles.ADMIN);
        // ADMIN manages REPORT_VERIFIER
        _setRoleAdmin(Roles.REPORT_VERIFIER, Roles.ADMIN);

        // Grant ADMIN to the initial updater admin
        _grantRole(Roles.ADMIN, initialAdmin);
    }
}
