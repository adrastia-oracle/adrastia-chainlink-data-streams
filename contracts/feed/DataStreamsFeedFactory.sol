// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {DataStreamsFeed} from "./DataStreamsFeed.sol";
import {Roles} from "../common/Roles.sol";

/**
 * @title DataStreamsFeedFactory
 * @author TRILEZ SOFTWARE INC. dba. Adrastia
 * @notice A factory contract for creating DataStreamsFeed contracts. Uses CREATE2 to deploy the contracts at a
 * deterministic address based on the provided parameters. Users can pass a salt to the factory to allow for multiple
 * deployments of the same feed with different addresses.
 */
contract DataStreamsFeedFactory {
    /**
     * @notice The address of the verifier proxy contract.
     */
    address public immutable verifierProxy;

    /**
     * @notice An errror thrown passing invalid constructor arguments.
     */
    error InvalidConstructorArguments();

    /**
     * @notice Emitted when a new DataStreamsFeed contract is created.
     *
     * @param creator The address of the account that created the feed.
     * @param feedAddress The address of the newly created DataStreamsFeed contract.
     * @param feedId The ID of the feed.
     * @param timestamp The timestamp when the feed was created.
     */
    event FeedCreated(address indexed creator, address indexed feedAddress, bytes32 indexed feedId, uint256 timestamp);

    /**
     * @notice Constructs a new DataStreamsFeedFactory contract.
     *
     * @param verifierProxy_ The address of the verifier proxy contract.
     */
    constructor(address verifierProxy_) {
        if (verifierProxy_ == address(0)) {
            // These are definitely invalid arguments
            revert InvalidConstructorArguments();
        }

        verifierProxy = verifierProxy_;
    }

    /**
     * @notice Creates a new DataStreamsFeed contract with the caller as the admin and without a verified report updater.
     *
     * @param feedId The ID of the feed to be created.
     * @param decimals The number of decimals for the feed.
     * @param description A description of the feed.
     *
     * @return addr The address of the newly created DataStreamsFeed contract.
     */
    function createFeed(
        bytes32 feedId,
        uint8 decimals,
        string memory description
    ) external virtual returns (address addr) {
        return createFeed(hex"", feedId, decimals, description, msg.sender, address(0));
    }

    /**
     * @notice Creates a new DataStreamsFeed contract.
     *
     * @param feedId The ID of the feed to be created.
     * @param decimals The number of decimals for the feed.
     * @param description A description of the feed.
     * @param admin The address of the admin for the new feed.
     * @param updater The address of the verified report updater, if any. Use the zero address to not grant this role.
     * WARNING: This address will be able to submit and update reports without verification. This address is intended
     * to be the address of an instance of the AdrastiaDataStreamsUpdater contract that handles verification in bulk.
     *
     * @return addr The address of the newly created DataStreamsFeed contract.
     */
    function createFeed(
        bytes32 feedId,
        uint8 decimals,
        string memory description,
        address admin,
        address updater
    ) external virtual returns (address addr) {
        return createFeed(hex"", feedId, decimals, description, admin, updater);
    }

    /**
     * @notice Creates a new DataStreamsFeed contract with a user-specified salt.
     *
     * @param userSalt The salt to use for the CREATE2 address computation. This salt is hashed with the creator address
     * and dynamic feed parameters to create a unique and deterministic address for the feed.
     * @param feedId The ID of the feed to be created.
     * @param decimals The number of decimals for the feed.
     * @param description A description of the feed.
     * @param admin The address of the admin for the new feed.
     * @param updater The address of the verified report updater, if any. Use the zero address to not grant this role.
     * WARNING: This address will be able to submit and update reports without verification. This address is intended
     * to be the address of an instance of the AdrastiaDataStreamsUpdater contract that handles verification in bulk.
     *
     * @return feedAddress The address of the newly created DataStreamsFeed contract.
     */
    function createFeed(
        bytes32 userSalt,
        bytes32 feedId,
        uint8 decimals,
        string memory description,
        address admin,
        address updater
    ) public virtual returns (address feedAddress) {
        require(admin != address(0), "Admin address cannot be zero");

        bytes memory bytecode = getBytecode(feedId, decimals, description);
        bytes32 finalSalt = keccak256(abi.encodePacked(msg.sender, userSalt, feedId, decimals, description));

        feedAddress = computeAddress(finalSalt, bytecode);
        require(feedAddress.code.length == 0, "Feed already deployed at computed address");

        assembly {
            // Skip the first 32 (0x20) bytes which store the length of the byte array
            feedAddress := create2(0, add(bytecode, 0x20), mload(bytecode), finalSalt)
            if iszero(extcodesize(feedAddress)) {
                revert(0, 0)
            }
        }

        // Grant the admin role to the specified admin address
        IAccessControl(feedAddress).grantRole(Roles.ADMIN, admin);

        if (updater != address(0)) {
            // The user specified an updater address, grant the REPORT_VERIFIER role to the updater
            IAccessControl(feedAddress).grantRole(Roles.REPORT_VERIFIER, updater);
        }

        // Renounce the admin role for the factory
        IAccessControl(feedAddress).renounceRole(Roles.ADMIN, address(this));

        emit FeedCreated(msg.sender, feedAddress, feedId, block.timestamp);
    }

    /**
     * @notice Computes the address of a DataStreamsFeed contract using CREATE2.
     *
     * @dev The salt is combined with the creator address and feed parameters to derive a unique final salt.
     * This prevents front-running and allows deterministic address computation.
     *
     * @param creator The address that will deploy the feed (used in salt derivation).
     * @param userSalt A user-supplied salt that can be reused safely across different feeds or creators.
     * @param feedId The ID of the feed.
     * @param decimals The number of decimals for the feed.
     * @param description A human-readable description of the feed.
     *
     * @return addr The predicted address of the feed if it were deployed with these parameters.
     */
    function computeFeedAddress(
        address creator,
        bytes32 userSalt,
        bytes32 feedId,
        uint8 decimals,
        string memory description
    ) external view virtual returns (address) {
        bytes memory bytecode = getBytecode(feedId, decimals, description);
        bytes32 finalSalt = keccak256(abi.encodePacked(creator, userSalt, feedId, decimals, description));

        return computeAddress(finalSalt, bytecode);
    }

    function getBytecode(
        bytes32 feedId,
        uint8 decimals,
        string memory description
    ) internal view virtual returns (bytes memory) {
        return
            abi.encodePacked(
                type(DataStreamsFeed).creationCode,
                abi.encode(verifierProxy, feedId, decimals, description)
            );
    }

    function computeAddress(bytes32 salt, bytes memory bytecode) internal view virtual returns (address) {
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode)));

        return address(uint160(uint256(hash)));
    }
}
