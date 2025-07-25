// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

import {AdrastiaDataStreamsCommon} from "../common/AdrastiaDataStreamsCommon.sol";
import {IDataStreamsFeed} from "../feed/IDataStreamsFeed.sol";

import {AutomationCompatibleInterface} from "../vendor/AutomationCompatibleInterface.sol";
import {IVerifierProxy} from "../vendor/IVerifierProxy.sol";
import {IFeeManager} from "../vendor/IFeeManager.sol";
import {Common} from "../vendor/Common.sol";
import {AggregatorV3Interface} from "../vendor/AggregatorV3Interface.sol";

/**
 * @title AdrastiaDataStreamsUpdater
 * @author Tyler Loewen, TRILEZ SOFTWARE INC. dba. Adrastia
 * @notice The Adrastia Data Streams Updater contract is responsible for updating registered Data Streams feeds with new
 * reports. It verifies the reports using the Chainlink verifier proxy and its verifyBulk function, then passes
 * the verified reports to the respective Data Streams feed for processing.
 *
 * Access is controlled using OpenZeppelin's AccessControlEnumerable, allowing for fine-grained permissions.
 * The roles are setup as follows:
 * - ADMIN: Can withdraw ERC20 and native tokens, and manage the role and sub-roles.
 *   - CONFIG_ADMIN: Can register, unregister, and change feeds.
 * - UPDATER_ADMIN: Can manage the ORACLE_UPDATER role.
 *   - ORACLE_UPDATER: Can call performUpkeep to update feeds.
 *
 * Granting the ORACLE_UPDATER role to `address(0)` allows anyone to call performUpkeep to update feeds.
 */
contract AdrastiaDataStreamsUpdater is
    AutomationCompatibleInterface,
    AdrastiaDataStreamsCommon,
    AccessControlEnumerable
{
    using EnumerableMap for EnumerableMap.Bytes32ToAddressMap;

    /**
     * @notice The action to take when registering or unregistering a feed.
     */
    enum FeedRegistrationAction {
        REGISTER,
        UNREGISTER
    }

    struct FeedIdAndAddress {
        bytes32 feedId;
        address feed;
    }

    bytes32 public constant ADMIN = keccak256("ADMIN_ROLE");

    bytes32 public constant CONFIG_ADMIN = keccak256("CONFIG_ADMIN_ROLE");

    bytes32 public constant UPDATER_ADMIN = keccak256("UPDATER_ADMIN_ROLE");

    bytes32 public constant ORACLE_UPDATER = keccak256("ORACLE_UPDATER_ROLE");

    /**
     * @notice The precision factor to use when calculating the change between two numbers.
     * @dev Fixed to 8 decimal places.
     */
    uint256 public constant CHANGE_PRECISION = 10 ** 8;

    /**
     * @notice The Chainlink verifier proxy contract.
     */
    IVerifierProxy public immutable verifierProxy;

    /**
     * @notice The mapping of feed IDs to their respective feed addresses.
     */
    EnumerableMap.Bytes32ToAddressMap internal _feedTargets;

    /**
     * @notice Emitted when a feed update is skipped due to the provided report timestamp being older than the stored
     * timestamp.
     *
     * @param feedId The feed ID.
     * @param feed The feed address.
     * @param storedTimestamp The stored timestamp of the feed.
     * @param providedTimestamp The provided timestamp of the report.
     * @param timestamp The timestamp of the event.
     */
    event FeedUpdateSkipped(
        bytes32 indexed feedId,
        address indexed feed,
        uint256 storedTimestamp,
        uint256 providedTimestamp,
        uint256 timestamp
    );

    /**
     * @notice Emitted when a feed update is performed successfully.
     *
     * @param feedId The feed ID.
     * @param feed The feed address.
     * @param timestamp The timestamp of the event.
     */
    event FeedUpdatePerformed(bytes32 indexed feedId, address indexed feed, uint256 timestamp);

    /**
     * @notice Emitted when a feed update fails.
     *
     * @param feedId The feed ID.
     * @param feed The feed address.
     * @param data The error data.
     * @param timestamp The timestamp of the event.
     */
    event FeedUpdateFailed(bytes32 indexed feedId, address indexed feed, bytes data, uint256 timestamp);

    /**
     * @notice Emitted when a feed is registered or unregistered.
     * @param feedId The feed ID.
     * @param action The action taken.
     * @param timestamp The timestamp of the event.
     */
    event FeedRegistrationChanged(bytes32 indexed feedId, FeedRegistrationAction indexed action, uint256 timestamp);

    /**
     * @notice Emitted when a feed target is changed.
     * @param feedId The feed ID.
     * @param oldFeed The old feed address.
     * @param newFeed The new feed address.
     * @param timestamp The timestamp of the event.
     */
    event FeedTargetChanged(
        bytes32 indexed feedId,
        address indexed oldFeed,
        address indexed newFeed,
        uint256 timestamp
    );

    /**
     * @notice Thrown when performing an operation using a feed ID that is not registered.
     * @param feedId The feed ID.
     */
    error FeedNotRegistered(bytes32 feedId);

    /**
     * @notice Thrown when a feed is already registered.
     * @param feedId The feed ID.
     */
    error FeedAlreadyRegistered(bytes32 feedId);

    /**
     * @notice Thrown when the provided feed ID does not match the expected feed ID.
     */
    error FeedMismatch(bytes32 expectedFeedId, bytes32 providedFeedId);

    /**
     * @notice Thrown when a feed is not changed.
     * @param feedId The feed ID.
     * @param feed The feed address.
     */
    error FeedNotChanged(bytes32 feedId, address feed);

    /**
     * @notice Thrown when no feeds were updated during a performUpkeep call.
     */
    error NoFeedsUpdated();

    /**
     * @notice Thrown when the verified reports length does not match the unverified reports length.
     * @param unverifiedReportsLength The length of the unverified reports.
     * @param verifiedReportsLength The length of the verified reports.
     */
    error ReportLengthMismatch(uint256 unverifiedReportsLength, uint256 verifiedReportsLength);

    /**
     * @notice Modifier to make a function callable only by a certain role. In addition to checking the sender's role,
     * `address(0)` 's role is also considered. Granting a role to `address(0)` is equivalent to enabling this role for
     * everyone.
     * @param role The role to check.
     */
    modifier onlyRoleOrOpenRole(bytes32 role) {
        if (!hasRole(role, address(0))) {
            if (!hasRole(role, msg.sender)) revert AccessControlUnauthorizedAccount(msg.sender, role);
        }
        _;
    }

    /**
     * @notice Constructs the Adrastia Data Streams Updater contract.
     * @param _verifierProxy The Chainlink verifier proxy contract.
     * @param initialAdmin The initial admin address.
     * @param initialUpdaterAdmin The initial updater admin address.
     */
    constructor(address _verifierProxy, address initialAdmin, address initialUpdaterAdmin) {
        if (_verifierProxy == address(0)) {
            revert("Invalid verifier proxy address");
        }

        if (initialAdmin == address(0) || initialUpdaterAdmin == address(0)) {
            revert("Invalid initial admins");
        }

        verifierProxy = IVerifierProxy(_verifierProxy);

        _initializeRoles(initialAdmin, initialUpdaterAdmin);

        approveVerifierFeeSpend();
    }

    /**
     * @notice Registers a new feed with the contract.
     * @param feedId The feed ID.
     * @param feed The feed address.
     */
    function registerFeed(bytes32 feedId, address feed) external virtual onlyRole(CONFIG_ADMIN) {
        bytes32 contractFeedId = _getIdFromFeed(feed);
        if (feedId != contractFeedId) {
            revert FeedMismatch(contractFeedId, feedId);
        }

        (bool feedExists_, address oldFeed) = _feedTargets.tryGet(feedId);
        if (feedExists_) {
            revert FeedAlreadyRegistered(feedId);
        }

        _feedTargets.set(feedId, feed);

        emit FeedRegistrationChanged(feedId, FeedRegistrationAction.REGISTER, block.timestamp);

        emit FeedTargetChanged(feedId, oldFeed, feed, block.timestamp);
    }

    /**
     * @notice Changes the feed address for a registered feed.
     * @param feedId The feed ID.
     * @param feed The new feed address.
     */
    function changeFeed(bytes32 feedId, address feed) external virtual onlyRole(CONFIG_ADMIN) {
        bytes32 contractFeedId = _getIdFromFeed(feed);
        if (feedId != contractFeedId) {
            revert FeedMismatch(contractFeedId, feedId);
        }

        (bool feedExists_, address oldFeed) = _feedTargets.tryGet(feedId);
        if (!feedExists_) {
            revert FeedNotRegistered(feedId);
        }

        if (oldFeed == feed) {
            revert FeedNotChanged(feedId, feed);
        }

        _feedTargets.set(feedId, feed);

        emit FeedTargetChanged(feedId, oldFeed, feed, block.timestamp);
    }

    /**
     * @notice Unregisters a feed from the contract.
     * @param feedId The feed ID.
     */
    function unregisterFeed(bytes32 feedId) external virtual onlyRole(CONFIG_ADMIN) {
        (bool feedExists_, address oldFeed) = _feedTargets.tryGet(feedId);
        if (!feedExists_) {
            revert FeedNotRegistered(feedId);
        }

        _feedTargets.remove(feedId);

        emit FeedTargetChanged(feedId, oldFeed, address(0), block.timestamp);

        emit FeedRegistrationChanged(feedId, FeedRegistrationAction.UNREGISTER, block.timestamp);
    }

    /**
     * @notice Gets the feed address for a given feed ID, if it exists.
     *
     * @param feedId The feed ID.
     *
     * @custom:throws FeedNotRegistered if the feed ID is not registered.
     *
     * @return The feed address.
     */
    function getFeed(bytes32 feedId) external view virtual returns (address) {
        (bool feedExists_, address targetFeed) = _feedTargets.tryGet(feedId);
        if (!feedExists_) {
            revert FeedNotRegistered(feedId);
        }

        return targetFeed;
    }

    /**
     * @notice Checks if a feed exists for a given feed ID.
     *
     * @param feedId The feed ID.
     *
     * @return True if the feed exists, false otherwise.
     */
    function feedExists(bytes32 feedId) external view virtual returns (bool) {
        return _feedTargets.contains(feedId);
    }

    /**
     * @notice Gets the number of registered feeds.
     *
     * @return The number of registered feeds.
     */
    function getFeedCount() external view virtual returns (uint256) {
        return _feedTargets.length();
    }

    /**
     * @notice Gets the feed IDs of all registered feeds.
     *
     * @return An array of feed IDs.
     */
    function getFeedIds() external view virtual returns (bytes32[] memory) {
        return _feedTargets.keys();
    }

    /**
     * @notice Gets all of the pairs of feed IDs and their respective feed addresses.
     *
     * @return An array of FeedIdAndAddress structs containing the feed ID and feed address.
     */
    function getFeedMapping() external view virtual returns (FeedIdAndAddress[] memory) {
        uint256 length = _feedTargets.length();
        FeedIdAndAddress[] memory feedMapping = new FeedIdAndAddress[](length);

        for (uint256 i = 0; i < length; ++i) {
            (bytes32 feedId, address feed) = _feedTargets.at(i);
            feedMapping[i] = FeedIdAndAddress({feedId: feedId, feed: feed});
        }

        return feedMapping;
    }

    /**
     * @notice Withdraws ERC20 tokens from the contract.
     * @param token The token address.
     * @param to The recipient address.
     * @param amount The amount to withdraw.
     */
    function withdrawErc20(address token, address to, uint256 amount) external virtual onlyRole(ADMIN) {
        SafeERC20.safeTransfer(IERC20(token), to, amount);
    }

    /**
     * @notice Withdraws native tokens from the contract.
     * @param to The recipient address.
     * @param amount The amount to withdraw.
     */
    function withdrawNative(address to, uint256 amount) external virtual onlyRole(ADMIN) {
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }

    /**
     * @notice Approves the current verifier reward manager to spend an unlimited amount of LINK.
     * @dev Can only be called once, unless the fee manager returns a different LINK address. Impotent otherwise.
     */
    function approveVerifierFeeSpend() public virtual {
        // Retrieve fee manager and reward manager
        IFeeManager feeManager = IFeeManager(address(verifierProxy.s_feeManager()));
        if (address(feeManager) == address(0)) {
            // Fees are disabled. Nothing to approve.
            return;
        }

        address rewardManager = feeManager.i_rewardManager();
        if (rewardManager == address(0)) {
            // No reward manager. Nothing to approve.
            return;
        }

        IERC20 feeToken = IERC20(feeManager.i_linkAddress());
        if (address(feeToken) == address(0)) {
            // No fee token. Nothing to approve.
            return;
        }

        uint256 allowance = feeToken.allowance(address(this), rewardManager);
        if (allowance == 0) {
            feeToken.approve(rewardManager, type(uint256).max);
        }
    }

    /**
     * @notice Checks if an update is needed for a specific price feed.
     * @dev The feed being checked must be registered with the contract.
     * @param checkData An array of bytes containing:
     * - feedId: First 32 bytes - The feed ID.
     * - updateThreshold: Second 32 bytes - The percentage change threshold that must be met for an update to be needed.
     * - heartbeat: Third 32 bytes - The maximum time in seconds since the last update before an update is needed.
     * - offchainPrice: Fourth 32 bytes - The offchain price to compare the current onchain value against.
     * - offchainPublishTime: Fifth 32 bytes - The timestamp of the offchain price.
     * @return upkeepNeeded True if an update is needed, false otherwise.
     * @return performData Encoded onchain price, timestamp, whether the heartbeat was triggered, and whether the price
     * deviation was triggered. The onchain price and timestamp will be zero if the onchain report is expired or missing.
     */
    function checkUpkeep(
        bytes memory checkData
    ) public view virtual returns (bool upkeepNeeded, bytes memory performData) {
        if (checkData.length != 160) {
            require(checkData.length >= 96, "Missing feed data.");

            if (checkData.length < 128) {
                revert("Missing offchain price.");
            }

            if (checkData.length < 160) {
                revert("Missing offchain timestamp.");
            }

            revert("Too much data.");
        }

        (
            bytes32 feedId,
            uint256 updateThreshold,
            uint256 heartbeat,
            int256 offchainPrice,
            uint256 offchainPublishTime
        ) = abi.decode(checkData, (bytes32, uint256, uint256, int256, uint256));

        (bool feedExists_, address targetFeed) = _feedTargets.tryGet(feedId);
        if (!feedExists_) {
            revert FeedNotRegistered(feedId);
        }

        (int256 price, uint256 timestamp) = readUnderlyingFeed(targetFeed);

        bool heartbeatTriggered = false;
        bool priceDeviationTriggered = false;

        // Only check trigger conditions if the offchain price is not older than the onchain price
        if (offchainPublishTime >= timestamp) {
            uint256 timeSinceUpdate = offchainPublishTime - timestamp;
            if (timeSinceUpdate >= heartbeat) {
                heartbeatTriggered = true;
            }

            (uint256 change, bool isMaximalChange) = calculateChange(price, offchainPrice);

            if (isMaximalChange || change >= updateThreshold) {
                priceDeviationTriggered = true;
            }
        }

        upkeepNeeded = heartbeatTriggered || priceDeviationTriggered;
        performData = abi.encode(price, timestamp, heartbeatTriggered, priceDeviationTriggered);
    }

    /**
     * @notice Updates the latest reports for registered feeds.
     * @param performData An encoded array of bytes representing the unverified reports.
     */
    function performUpkeep(bytes calldata performData) external payable virtual onlyRoleOrOpenRole(ORACLE_UPDATER) {
        bytes[] memory unverifiedReports = abi.decode(performData, (bytes[]));

        // Retrieve fee manager and reward manager
        IFeeManager feeManager = IFeeManager(address(verifierProxy.s_feeManager()));

        // Set the fee token address (LINK in this case)
        address feeTokenAddress;

        if (address(feeManager) == address(0)) {
            // No fee manager. Fees are disabled.
            feeTokenAddress = address(0);
        } else {
            feeTokenAddress = feeManager.i_linkAddress();
        }

        bytes[] memory verifiedReports = verifierProxy.verifyBulk(unverifiedReports, abi.encode(feeTokenAddress));
        if (verifiedReports.length != unverifiedReports.length) {
            revert ReportLengthMismatch(unverifiedReports.length, verifiedReports.length);
        }

        uint256 successCount = 0;

        for (uint256 i = 0; i < unverifiedReports.length; ++i) {
            // Decode unverified report to extract report data
            (, bytes memory reportData) = abi.decode(unverifiedReports[i], (bytes32[3], bytes));

            // Extract report version from reportData
            uint16 reportVersion = (uint16(uint8(reportData[0])) << 8) | uint16(uint8(reportData[1]));

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
            (, uint256 storedTimestamp) = readUnderlyingFeed(targetFeed);
            if (storedTimestamp >= feedObservationsTimestamp) {
                // The provided report is old, skip it
                emit FeedUpdateSkipped(feedId, targetFeed, storedTimestamp, feedObservationsTimestamp, block.timestamp);

                continue;
            }

            // Attempt to write the report to the data stream
            (bool success, bytes memory data) = targetFeed.call(
                abi.encodeWithSelector(IDataStreamsFeed.updateReport.selector, reportVersion, verifiedReports[i])
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

    /**
     * @notice Reads the latest onchain price and timestamp for a Data Streams feed.
     * @param feed The feed address.
     * @return price The latest onchain price.
     * @return timestamp The timestamp of the latest onchain price.
     */
    function readUnderlyingFeed(address feed) internal view virtual returns (int256 price, uint256 timestamp) {
        (bool success, bytes memory data) = feed.staticcall(
            abi.encodeWithSelector(AggregatorV3Interface.latestRoundData.selector)
        );
        if (!success) {
            // The call fails if the report is expired or missing. Return zeros to signal this.
            return (0, 0);
        } else {
            // startedAt contains the observationsTimestamp, which is the timestamp of the latest report.
            (, int256 answer, uint256 startedAt, , ) = abi.decode(data, (uint80, int256, uint256, uint256, uint80));

            return (answer, startedAt);
        }
    }

    /**
     * @notice Calculates the change between two numbers, scaled by the CHANGE_PRECISION.
     * @param a A number.
     * @param b Another number.
     * @return change The normalized percentage change between a and b. See Adrastia Documentation (docs.adrastia.io)
     * for more information regarding normalization.
     * @return maximalChange If one value is zero and other is non-zero, returns true. If the change is so large that
     * overflow occurs, returns true. Otherwise, returns false. If one value is negative, and the other is non-negative,
     * returns true.
     */
    function calculateChange(int256 a, int256 b) internal pure virtual returns (uint256 change, bool maximalChange) {
        // If one is zero and the other is not, treat as maximal change
        if (a == 0 && b == 0) {
            return (0, false);
        } else if (a == 0 || b == 0) {
            return (0, true);
        }

        unchecked {
            // Check for sign flips
            if ((a > 0 && b < 0) || (a < 0 && b > 0)) {
                return (0, true); // sign flip = maximum deviation
            }

            int256 delta = a - b;

            // We use absolute change scaled by CHANGE_PRECISION, divided by absolute base
            uint256 uDelta = uint256(delta >= 0 ? delta : -delta);
            uint256 uBase = uint256(b >= 0 ? b : -b);
            uint256 preciseDelta = uDelta * CHANGE_PRECISION;

            if (preciseDelta / CHANGE_PRECISION != uDelta) {
                // multiplication overflow
                return (0, true);
            }

            change = preciseDelta / uBase;
            maximalChange = false;
        }
    }

    /**
     * @notice Gets the feed ID for a given feed address from the feed contract itself. Used to verify that the feed ID
     * matches the expected feed ID.
     *
     * @param feed The feed address.
     *
     * @return The feed ID.
     */
    function _getIdFromFeed(address feed) internal view virtual returns (bytes32) {
        return IDataStreamsFeed(feed).feedId();
    }

    function _initializeRoles(address initialAdmin, address initialUpdaterAdmin) internal virtual {
        // Admin self manages its own role
        _setRoleAdmin(ADMIN, ADMIN);

        // Admin manages the config admin role
        _setRoleAdmin(CONFIG_ADMIN, ADMIN);

        // Oracle updater admin self manages its own role
        _setRoleAdmin(UPDATER_ADMIN, UPDATER_ADMIN);

        // Oracle updater admin manages the oracle updater role
        _setRoleAdmin(ORACLE_UPDATER, UPDATER_ADMIN);

        // Grant the admin role to the initial admin
        _grantRole(ADMIN, initialAdmin);

        // Grant the updater admin role to the initial updater admin
        _grantRole(UPDATER_ADMIN, initialUpdaterAdmin);
    }
}
