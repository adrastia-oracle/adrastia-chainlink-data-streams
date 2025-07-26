// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {AggregatorV2V3Interface} from "../vendor/AggregatorV2V3Interface.sol";
import {AggregatorInterface} from "../vendor/AggregatorV2V3Interface.sol";
import {AggregatorV3Interface} from "../vendor/AggregatorV2V3Interface.sol";
import {DataStreamsStructs} from "../vendor/DataStreamsStructs.sol";
import {AdrastiaDataStreamsCommon} from "../common/AdrastiaDataStreamsCommon.sol";
import {IDataStreamsFeed} from "./IDataStreamsFeed.sol";
import {IVerifierProxy} from "../vendor/IVerifierProxy.sol";
import {IFeeManager} from "../vendor/IFeeManager.sol";
import {Roles} from "../common/Roles.sol";
import {IDataStreamsPreUpdateHook} from "./hooks/IDataStreamsPreUpdateHook.sol";
import {IDataStreamsPostUpdateHook} from "./hooks/IDataStreamsPostUpdateHook.sol";

/**
 * @title DataStreamsFeed
 * @author Tyler Loewen, TRILEZ SOFTWARE INC. dba. Adrastia
 * @notice The Data Streams contract is responsible for storing and serving the latest report data from Chainlink
 * Data Streams feeds.
 *
 * Access is controlled using OpenZeppelin's AccessControlEnumerable, allowing for fine-grained permissions.
 * The roles are setup as follows:
 * - ADMIN: Can manage the role and sub-roles. Cam witjdraw ERC20 tokens from the contract. Can set the update
 *  hook configuration.
 *   - REPORT_VERIFIER: Can call `updateReport` to update the latest report data. Ideally, accounts with this role
 *     should be the Adrastia Data Streams Updater contract that verifies reports in bulk. This role is not required
 *     when using the `verifyAndUpdateReport` function, as that function will verify the report before updating it.
 *   - UPDATE_PAUSE_ADMIN: Can pause and unpause the update functionality of the contract. This is useful for emergency
 *     situations or maintenance.
 *
 * This contract implements Chainlink's AggregatorV2V3Interface, allowing for easy integration with existing protocols.
 * Round IDs start at 1 and increment with each report update, allowing for over a hundred years of unique round IDs.
 *
 * The functions `latestAnswer` and `latestRoundData` will revert if the latest report is expired or if there is no
 * report. The functions `latestTimestamp` and `latestRound` do not revert if the latest report is expired to allow
 * for introspection of the latest report data, even if it is expired. This is useful for anyone querying past rounds
 * using `latestRound`. Functions that return report data for specific round IDs do not check for expiration, as they
 * are expected to be used for historical data retrieval.
 *
 * Updates to the feed can be paused using the `setPaused` function, which can only be called by accounts with the
 * UPDATE_PAUSE_ADMIN role. This is useful for emergency situations or maintenance.
 *
 * The `setHookConfig` function allows for setting a hooks before or after a report is updated.
 */
contract DataStreamsFeed is
    IDataStreamsFeed,
    AggregatorV2V3Interface,
    AdrastiaDataStreamsCommon,
    DataStreamsStructs,
    AccessControlEnumerable,
    ReentrancyGuard
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
     * @notice Hook configuration.
     */
    struct Hook {
        /**
         * @notice A flag indicating whether the hook is allowed to fail. If true, the hook can fail without reverting
         * the transaction.
         */
        bool allowHookFailure;
        /**
         * @notice The gas limit for the hook. This is used to ensure that the hook does not consume too much gas and
         * cause the transaction unintentially to fail.
         *
         * @dev This is a uint64 to save on storage costs, as the gas limit is typically a small number.
         */
        uint64 hookGasLimit;
        /**
         * @notice The address of the hook. The zero address indicates that no post-update hook is set.
         */
        address hookAddress;
    }

    /**
     * @notice A struct to store pause status and update hook configuration.
     */
    struct ConfigAndState {
        /**
         * @notice A flag indicating whether updates to the feed are paused. If true, no new reports can be written.
         */
        bool updatesPaused;
        /**
         * @notice A bitfield of active hook types.
         * @dev Up to 16 hook types can be supported.
         */
        uint16 activeHookTypes;
    }

    enum HookType {
        PreUpdate, // onPreReportUpdate is called immediately before pushing a new report
        PostUpdate // onPostReportUpdate is called immediately after pushing a new report
    }

    /**
     * @notice The Chainlink verifier proxy contract.
     */
    IVerifierProxy public immutable override verifierProxy;

    /**
     * @notice The number of decimals used in the feed. This is the same as the decimals used in the report.
     */
    uint8 public immutable override decimals;

    /**
     * @notice The description of the feed.
     */
    string public override description;

    /**
     * @notice The ID of the feed. This is the same as the feedId in the report.
     */
    bytes32 internal immutable _feedId;

    /**
     * @notice The latest report data.
     */
    TruncatedReport internal latestReport;

    /**
     * @notice The configuration and state of the feed.
     *
     * @dev This is used to store the updatesPaused flag and the updateHook address.
     */
    ConfigAndState internal configAndState;

    /**
     * @notice Maps a hook type to its hook configuration.
     */
    mapping(uint256 => Hook) internal hooks;

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
     * @notice An event emitted when the update pause status is changed.
     *
     * @param caller The address of the account that changed the pause status.
     * @param paused True if updates are paused, false otherwise.
     * @param timestamp The block timestamp at which the pause status was changed, in seconds since the Unix epoch.
     */
    event PauseStatusChanged(address indexed caller, bool paused, uint256 timestamp);

    /**
     * @notice An event emitted when a hook reverts, but the failure is allowed.
     *
     * @param hookType The type of the hook that failed.
     * @param hook The address of the hook that failed.
     * @param reason The reason for the failure, encoded as bytes.
     * @param timestamp The block timestamp at which the hook failed, in seconds since the Unix epoch.
     */
    event HookFailed(uint256 indexed hookType, address indexed hook, bytes reason, uint256 timestamp);

    /**
     * @notice An event emitted when a hook is changed.
     *
     * @param caller The address of the account that changed the hook.
     * @param hookType The type of the hook that was changed.
     * @param oldHook The old hook config.
     * @param newHook The new hook config.
     * @param timestamp The block timestamp at which the hook was changed, in seconds since the Unix epoch.
     */
    event HookConfigUpdated(
        address indexed caller,
        uint256 indexed hookType,
        Hook oldHook,
        Hook newHook,
        uint256 timestamp
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
     * @notice An error thrown when attempting to update the report, but updates are paused.
     */
    error UpdatesPaused();

    /**
     * @notice An error thrown when a hook fails to execute.
     *
     * @param hookType The type of the hook that failed.
     * @param hookAddress The address of the hook that failed.
     * @param reason The reason for the failure, encoded as bytes.
     */
    error HookFailedError(uint256 hookType, address hookAddress, bytes reason);

    /**
     * @notice An error thrown when attempting to set the paused status of the feed, but the status did not change.
     */
    error PauseStatusNotChanged();

    /**
     * @notice An error thrown when attempting to set a hook, but the hook did not change.
     *
     * @param hookType The type of the hook that was not changed.
     */
    error HookConfigUnchanged(uint256 hookType);

    /**
     * @notice An error thrown when the hook configuration is invalid.
     */
    error InvalidHookConfig(uint256 hookType);

    /**
     * @notice An error thrown when a hook does not support the expected interface.
     *
     * @param hookType The type of the hook that does not support the interface.
     * @param hookAddress The address of the hook that does not support the interface.
     * @param interfaceId The interface ID that the hook is expected to support.
     */
    error HookDoesntSupportInterface(uint256 hookType, address hookAddress, bytes4 interfaceId);

    /**
     * @notice An error thrown when an invalid hook type is provided.
     */
    error InvalidHookType(uint256 hookType);

    /**
     * @notice Constructs a new DataStreamsFeed contract, granting the ADMIN role to the creator of the contract.
     *
     * @param verifierProxy_ The address of the Chainlink verifier proxy contract.
     * @param feedId_ The ID of the feed. This is the same as the feedId in the report.
     * @param decimals_ The number of decimals used in the feed. This is the same as the decimals used in the report.
     * @param description_ The description of the feed.
     */
    constructor(address verifierProxy_, bytes32 feedId_, uint8 decimals_, string memory description_) {
        if (verifierProxy_ == address(0) || feedId_ == bytes32(0)) {
            // These are definitely invalid arguments
            revert InvalidConstructorArguments();
        }

        verifierProxy = IVerifierProxy(verifierProxy_);
        _feedId = feedId_;
        decimals = decimals_;
        description = description_;

        latestReport = TruncatedReport(0, 0, 0, 0, 0);
        configAndState = ConfigAndState({
            updatesPaused: false,
            activeHookTypes: 0 // No hooks are active by default
        });

        _initializeRoles(msg.sender);
    }

    /**
     * @notice Returns the ID of the feed. This is the same as the feedId in the report.
     *
     * @return The ID of the feed.
     */
    function feedId() external view virtual override returns (bytes32) {
        return _feedId;
    }

    /**
     * @notice Determines whether updates to the feed are paused.
     *
     * @return True if updates are paused, false otherwise.
     */
    function paused() external view virtual returns (bool) {
        return configAndState.updatesPaused;
    }

    /**
     * @notice Sets whether updates to the feed are paused.
     * @dev This function can only be called by accounts with the UPDATE_PAUSE_ADMIN role.
     *
     * @param paused_  True to pause updates, false to allow updates.
     */
    function setPaused(bool paused_) external virtual onlyRole(Roles.UPDATE_PAUSE_ADMIN) {
        ConfigAndState storage _configAndState = configAndState;
        if (_configAndState.updatesPaused == paused_) {
            // The pause status did not change. Revert to help the user be aware of this.
            revert PauseStatusNotChanged();
        }

        configAndState.updatesPaused = paused_;

        emit PauseStatusChanged(msg.sender, paused_, block.timestamp);
    }

    /**
     * @notice Gets the hook configuration for a specific hook type. A zero address indicates that no hook is set.
     *
     * @param hookType The type of the hook to retrieve the configuration for.
     *
     * @return The configuration of the hook, including whether it allows failure, the gas limit for the hook, and the
     * address of the hook.
     */
    function getHookConfig(uint8 hookType) external view virtual returns (Hook memory) {
        return hooks[hookType];
    }

    /**
     * @notice Sets the hook configuration for a specific hook type.
     *
     * If the hookAddress is set to the zero address, it indicates that no post-update hook is set. In that case,
     * hookGasLimit must be 0 and allowHookFailure must be false to prevent accidental misconfiguration.
     *
     * If the hookAddress is set to a non-zero address, hookGasLimit must be non-zero to prevent accidental
     * misconfiguration.
     *
     * Please ensure that the hook implements ERC165 and supports the expected interface for the hook type.
     *
     * @dev This function can only be called by accounts with the ADMIN role.
     *
     * @param hookType The type of the hook to set the configuration for.
     * @param hookConfig The configuration of the hook to set, including whether it allows failure, the gas limit for
     * the hook, and the address of the hook.
     */
    function setHookConfig(uint8 hookType, Hook calldata hookConfig) external virtual onlyRole(Roles.ADMIN) {
        if (address(hookConfig.hookAddress) == address(0)) {
            // hookGasLimit must be 0 and allowHookFailure must be false if the hookAddress is zero
            // This is to prevent accidental misconfiguration
            if (hookConfig.hookGasLimit != 0 || hookConfig.allowHookFailure) {
                revert InvalidHookConfig(hookType);
            }
        } else {
            // We have an update hook. Ensure that hookGasLimit is not zero. If so, it's likely a misconfiguration.
            if (hookConfig.hookGasLimit == 0) {
                revert InvalidHookConfig(hookType);
            }
        }

        Hook memory oldHook = _getHook(hookType);

        if (
            oldHook.allowHookFailure == hookConfig.allowHookFailure &&
            oldHook.hookGasLimit == hookConfig.hookGasLimit &&
            oldHook.hookAddress == hookConfig.hookAddress
        ) {
            // The hook did not change. Revert to help the user be aware of this.
            revert HookConfigUnchanged(hookType);
        }

        if (address(hookConfig.hookAddress) != address(0)) {
            // Ensure that the hook supports the expected interface
            bytes4 expectedInterfaceId = _getHookInterfaceId(hookType);
            if (!ERC165Checker.supportsInterface(hookConfig.hookAddress, expectedInterfaceId)) {
                revert HookDoesntSupportInterface(hookType, hookConfig.hookAddress, expectedInterfaceId);
            }
        }

        if (address(hookConfig.hookAddress) != address(0)) {
            // We are setting a new hook, so we need to add it to the active hook types
            configAndState.activeHookTypes |= (uint16(1) << hookType);
        } else {
            // We are removing a hook, so we need to remove it from the active hook types
            configAndState.activeHookTypes &= ~(uint16(1) << hookType);
        }

        hooks[hookType] = hookConfig;

        emit HookConfigUpdated(msg.sender, hookType, oldHook, hookConfig, block.timestamp);
    }

    /**
     * @notice Returns the version of the contract.
     *
     * @return The version of the contract.
     */
    function version() external pure virtual override returns (uint256) {
        return 1;
    }

    /**
     * @notice Returns the latest price, if available and not expired.
     * @dev This function will revert if the latest report is expired or if there is no report.
     *
     * @return The latest report price.
     */
    function latestAnswer() external view virtual override returns (int256) {
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
    function latestTimestamp() external view virtual override returns (uint256) {
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
    function latestRound() external view virtual override returns (uint256) {
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
    function getAnswer(uint256 roundId) external view virtual override returns (int256) {
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
    function getTimestamp(uint256 roundId) external view virtual override returns (uint256) {
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
        virtual
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
        virtual
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
    ) external virtual override onlyRole(Roles.REPORT_VERIFIER) nonReentrant {
        _updateReport(reportVersion, verifiedReportData);
    }

    /// @inheritdoc IDataStreamsFeed
    function verifyAndUpdateReport(
        bytes calldata unverifiedReportData,
        bytes calldata parameterPayload
    ) external virtual override nonReentrant {
        // Decode unverified report to extract report data
        (, bytes memory reportData) = abi.decode(unverifiedReportData, (bytes32[3], bytes));

        // Extract report version from reportData
        uint16 reportVersion = (uint16(uint8(reportData[0])) << 8) | uint16(uint8(reportData[1]));

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

    /**
     * @notice The hash of the UPDATE_PAUSE_ADMIN role.
     *
     * @return The hash of the UPDATE_PAUSE_ADMIN role.
     */
    function UPDATE_PAUSE_ADMIN() external pure returns (bytes32) {
        return Roles.UPDATE_PAUSE_ADMIN;
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceID) public view virtual override returns (bool) {
        return
            interfaceID == type(IDataStreamsFeed).interfaceId ||
            interfaceID == type(AggregatorV2V3Interface).interfaceId ||
            interfaceID == type(AggregatorInterface).interfaceId ||
            interfaceID == type(AggregatorV3Interface).interfaceId ||
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

    function _getHookInterfaceId(uint256 hookType) internal pure virtual returns (bytes4) {
        if (hookType == uint256(HookType.PreUpdate)) {
            return type(IDataStreamsPreUpdateHook).interfaceId;
        } else if (hookType == uint256(HookType.PostUpdate)) {
            return type(IDataStreamsPostUpdateHook).interfaceId;
        } else {
            revert InvalidHookType(hookType);
        }
    }

    function _isHookSet(uint256 activeHooks, uint256 hookType) internal view virtual returns (bool) {
        return (activeHooks & (uint256(1) << hookType)) != 0;
    }

    function _getHook(uint256 hookType) internal view virtual returns (Hook memory) {
        return hooks[hookType];
    }

    /**
     * @notice Updates the latest report data.
     *
     * @param reportVersion The version of the report data. Must be either 2, 3, or 4.
     * @param verifiedReportData The verified report data, generated by the verifier proxy.
     */
    function _updateReport(uint16 reportVersion, bytes memory verifiedReportData) internal virtual {
        ConfigAndState memory config = configAndState;
        if (config.updatesPaused) {
            revert UpdatesPaused();
        }

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

        if (reportFeedId != _feedId) {
            revert FeedMismatch(_feedId, reportFeedId);
        }

        if (reportTimestamp == 0) {
            // The report is invalid
            revert InvalidReport();
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

        uint32 newRoundId = lastReport.roundId + 1;

        if (_isHookSet(config.activeHookTypes, uint256(HookType.PreUpdate))) {
            Hook memory preUpdateHook = _getHook(uint256(HookType.PreUpdate));

            (bool success, bytes memory returnData) = preUpdateHook.hookAddress.call{gas: preUpdateHook.hookGasLimit}(
                abi.encodeWithSelector(
                    IDataStreamsPreUpdateHook.onPreReportUpdate.selector,
                    _feedId,
                    newRoundId,
                    reportPrice,
                    reportTimestamp,
                    reportExpiresAt,
                    uint32(block.timestamp)
                )
            );

            if (!success) {
                if (preUpdateHook.allowHookFailure) {
                    // The hook failed, but we allow it to fail
                    emit HookFailed(
                        uint256(HookType.PreUpdate),
                        preUpdateHook.hookAddress,
                        returnData,
                        block.timestamp
                    );
                } else {
                    // The hook failed, and we do not allow it to fail
                    revert HookFailedError(uint256(HookType.PreUpdate), preUpdateHook.hookAddress, returnData);
                }
            }
        }

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

        if (_isHookSet(config.activeHookTypes, uint256(HookType.PostUpdate))) {
            Hook memory postUpdateHook = _getHook(uint256(HookType.PostUpdate));

            (bool success, bytes memory returnData) = postUpdateHook.hookAddress.call{gas: postUpdateHook.hookGasLimit}(
                abi.encodeWithSelector(
                    IDataStreamsPostUpdateHook.onPostReportUpdate.selector,
                    _feedId,
                    newRoundId,
                    reportPrice,
                    reportTimestamp,
                    reportExpiresAt,
                    uint32(block.timestamp)
                )
            );

            if (!success) {
                if (postUpdateHook.allowHookFailure) {
                    // The hook failed, but we allow it to fail
                    emit HookFailed(
                        uint256(HookType.PostUpdate),
                        postUpdateHook.hookAddress,
                        returnData,
                        block.timestamp
                    );
                } else {
                    // The hook failed, and we do not allow it to fail
                    revert HookFailedError(uint256(HookType.PostUpdate), postUpdateHook.hookAddress, returnData);
                }
            }
        }
    }

    function _initializeRoles(address initialAdmin) internal virtual {
        // ADMIN self administer their role
        _setRoleAdmin(Roles.ADMIN, Roles.ADMIN);
        // ADMIN manages REPORT_VERIFIER
        _setRoleAdmin(Roles.REPORT_VERIFIER, Roles.ADMIN);
        // ADMIN manages UPDATE_PAUSE_ADMIN
        _setRoleAdmin(Roles.UPDATE_PAUSE_ADMIN, Roles.ADMIN);

        // Grant ADMIN to the initial updater admin
        _grantRole(Roles.ADMIN, initialAdmin);
    }
}
