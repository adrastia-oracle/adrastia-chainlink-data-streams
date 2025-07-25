// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IAccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/IAccessControlEnumerable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Vm} from "forge-std/Vm.sol";
import {FeedConstants} from "../../FeedConstants.sol";
import {FeedDataFixture} from "../../FeedDataFixture.sol";
import {DataStreamsFeed} from "../../../feed/DataStreamsFeed.sol";
import {IVerifierProxy} from "../../../vendor/IVerifierProxy.sol";
import {VerifierStub} from "../../VerifierStub.sol";
import {AdrastiaDataStreamsUpdater} from "../../../updater/AdrastiaDataStreamsUpdater.sol";
import {FakeErc20} from "../../FakeErc20.sol";
import {FeeManagerStub} from "../../FeeManagerStub.sol";
import {RewardManagerStub} from "../../RewardManagerStub.sol";
import {FeedStub} from "../../FeedStub.sol";
import {UpdaterStub} from "../../UpdaterStub.sol";

contract UpdaterTest is Test, FeedConstants, FeedDataFixture {
    VerifierStub internal verifierStub;

    FeedStub internal ethUsdV3Feed;
    FeedStub internal btcUsdV3Feed;

    FeedStub internal ethUsdV3Feed2;
    FeedStub internal btcUsdV3Feed2;

    uint32 internal constant DEFAULT_HEARTBEAT = 60; // 1 minute
    uint256 internal constant DEFAULT_UPDATE_THRESHOLD = 10 ** 6; // 1% (8 decimals of precision)

    function setUp() public {
        vm.warp(1752791789);

        verifierStub = new VerifierStub();

        ethUsdV3Feed = new FeedStub(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );
        ethUsdV3Feed2 = new FeedStub(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        btcUsdV3Feed = new FeedStub(
            address(verifierStub),
            BTC_USD_V3.feedId,
            BTC_USD_V3.decimals,
            BTC_USD_V3.description
        );
        btcUsdV3Feed2 = new FeedStub(
            address(verifierStub),
            BTC_USD_V3.feedId,
            BTC_USD_V3.decimals,
            BTC_USD_V3.description
        );
    }

    function test_constructor_deploysCorrectly() public {
        address initialAdmin = address(0x123);
        address initialUpdaterAdmin = address(0x456);

        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            initialAdmin,
            initialUpdaterAdmin
        );

        bytes32 adminRole = updater.ADMIN();
        bytes32 updaterAdminRole = updater.UPDATER_ADMIN();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();

        // Assert the verifier proxy address
        assertEq(address(updater.verifierProxy()), address(verifierStub), "Verifier proxy address should match");

        // Assert the roles
        assertTrue(updater.hasRole(adminRole, initialAdmin), "Initial admin should have admin role");
        assertTrue(
            updater.hasRole(updaterAdminRole, initialUpdaterAdmin),
            "Initial updater admin should have updater admin role"
        );
        assertEq(updater.getRoleMemberCount(configAdminRole), 0, "There should be no config admins initially");
        assertEq(updater.getRoleMemberCount(oracleUpdaterRole), 0, "There should be no oracle updaters initially");
        assertEq(updater.getRoleMemberCount(adminRole), 1, "There should be one admin initially");
        assertEq(updater.getRoleMemberCount(updaterAdminRole), 1, "There should be one updater admin initially");

        // Assert that the feed count is zero
        assertEq(updater.getFeedCount(), 0, "Initial feed count should be zero");
        // Assert that the feed addresses are empty
        assertEq(updater.getFeedIds().length, 0, "Initial feed IDs should be empty");
        // Assert that the feed addresses mapping is empty
        assertEq(updater.getFeedMapping().length, 0, "Initial feed mapping should be empty");
    }

    function test_constructor_revertsWhenAdminIsZero() public {
        vm.expectRevert("Invalid initial admins");
        new AdrastiaDataStreamsUpdater(address(verifierStub), address(0), address(0));
    }

    function test_constructor_revertsWhenUpdaterAdminIsZero() public {
        vm.expectRevert("Invalid initial admins");
        new AdrastiaDataStreamsUpdater(address(verifierStub), address(0x123), address(0));
    }

    function test_constructor_revertsWhenVerifierProxyIsZero() public {
        vm.expectRevert("Invalid verifier proxy address");
        new AdrastiaDataStreamsUpdater(address(0), address(0x123), address(0x456));
    }

    function test_registerFeed_revertsWhenNotConfigAdmin() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        address unauthorizedUser = address(0x789);
        vm.startPrank(unauthorizedUser);
        bytes32 requiredRole = updater.CONFIG_ADMIN();

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                requiredRole
            )
        );
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
    }

    function test_registerFeed_revertWhenFeedIdMismatch() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        vm.expectRevert(
            abi.encodeWithSelector(
                AdrastiaDataStreamsUpdater.FeedMismatch.selector,
                ETH_USD_V3.feedId, // contract feedId
                BTC_USD_V3.feedId // provided feedId
            )
        );
        updater.registerFeed(BTC_USD_V3.feedId, address(ethUsdV3Feed));
    }

    function test_registerFeed_revertsWhenFeedAlreadyRegistered() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        // Now try to register it again
        vm.expectRevert(
            abi.encodeWithSelector(AdrastiaDataStreamsUpdater.FeedAlreadyRegistered.selector, ETH_USD_V3.feedId)
        );
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
    }

    function test_registerFeed_registersOneFeed() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedRegistrationChanged(
            ETH_USD_V3.feedId,
            AdrastiaDataStreamsUpdater.FeedRegistrationAction.REGISTER,
            block.timestamp
        );

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedTargetChanged(
            ETH_USD_V3.feedId,
            address(0),
            address(ethUsdV3Feed),
            block.timestamp
        );

        // Register the feed
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        bytes32[] memory feedIds = updater.getFeedIds();
        AdrastiaDataStreamsUpdater.FeedIdAndAddress[] memory feedAddresses = updater.getFeedMapping();

        // Assert that the feed is registered
        assertTrue(updater.feedExists(ETH_USD_V3.feedId), "Feed should be registered after successful registration");
        assertEq(
            updater.getFeed(ETH_USD_V3.feedId),
            address(ethUsdV3Feed),
            "Feed address should match the registered feed address"
        );
        assertEq(updater.getFeedCount(), 1, "Feed count should be 1 after registration");
        assertEq(feedIds.length, 1, "Feed IDs length should be 1 after registration");
        assertEq(feedAddresses.length, 1, "Feed addresses length should be 1 after registration");
        assertEq(feedIds[0], ETH_USD_V3.feedId, "Feed ID should match the registered feed ID");
        assertEq(feedAddresses[0].feedId, ETH_USD_V3.feedId, "Feed address ID should match the registered feed ID");
        assertEq(feedAddresses[0].feed, address(ethUsdV3Feed), "Feed address should match the registered feed address");
    }

    function test_registerFeed_registersTwoFeeds() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedRegistrationChanged(
            ETH_USD_V3.feedId,
            AdrastiaDataStreamsUpdater.FeedRegistrationAction.REGISTER,
            block.timestamp
        );

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedTargetChanged(
            ETH_USD_V3.feedId,
            address(0),
            address(ethUsdV3Feed),
            block.timestamp
        );

        // Register the first feed
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedRegistrationChanged(
            BTC_USD_V3.feedId,
            AdrastiaDataStreamsUpdater.FeedRegistrationAction.REGISTER,
            block.timestamp
        );

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedTargetChanged(
            BTC_USD_V3.feedId,
            address(0),
            address(btcUsdV3Feed),
            block.timestamp
        );

        // Register the second feed
        updater.registerFeed(BTC_USD_V3.feedId, address(btcUsdV3Feed));

        bytes32[] memory feedIds = updater.getFeedIds();
        AdrastiaDataStreamsUpdater.FeedIdAndAddress[] memory feedAddresses = updater.getFeedMapping();

        // Assert that both feeds are registered
        assertTrue(updater.feedExists(ETH_USD_V3.feedId), "ETH/USD feed should be registered");
        assertEq(
            updater.getFeed(ETH_USD_V3.feedId),
            address(ethUsdV3Feed),
            "Feed address should match the registered feed address"
        );
        assertTrue(updater.feedExists(BTC_USD_V3.feedId), "BTC/USD feed should be registered");
        assertEq(
            updater.getFeed(BTC_USD_V3.feedId),
            address(btcUsdV3Feed),
            "Feed address should match the registered feed address"
        );
        assertEq(updater.getFeedCount(), 2, "Feed count should be 2 after registering two feeds");
        assertEq(feedIds.length, 2, "Feed IDs length should be 2 after registering two feeds");
        assertEq(feedAddresses.length, 2, "Feed addresses length should be 2 after registering two feeds");

        // Assert the first feed details
        assertEq(feedIds[0], ETH_USD_V3.feedId, "First feed ID should match the registered ETH/USD feed ID");
        assertEq(
            feedAddresses[0].feedId,
            ETH_USD_V3.feedId,
            "First feed address ID should match the registered ETH/USD feed ID"
        );
        assertEq(
            feedAddresses[0].feed,
            address(ethUsdV3Feed),
            "First feed address should match the registered ETH/USD feed address"
        );

        // Assert the second feed details
        assertEq(feedIds[1], BTC_USD_V3.feedId, "Second feed ID should match the registered BTC/USD feed ID");
        assertEq(
            feedAddresses[1].feedId,
            BTC_USD_V3.feedId,
            "Second feed address ID should match the registered BTC/USD feed ID"
        );
        assertEq(
            feedAddresses[1].feed,
            address(btcUsdV3Feed),
            "Second feed address should match the registered BTC/USD feed address"
        );
    }

    function test_registerFeed_canRegisterAfterUnregister() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
        // Unregister the feed
        updater.unregisterFeed(ETH_USD_V3.feedId);

        // Now register it again
        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedRegistrationChanged(
            ETH_USD_V3.feedId,
            AdrastiaDataStreamsUpdater.FeedRegistrationAction.REGISTER,
            block.timestamp
        );
        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedTargetChanged(
            ETH_USD_V3.feedId,
            address(0),
            address(ethUsdV3Feed),
            block.timestamp
        );
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        bytes32[] memory feedIds = updater.getFeedIds();
        AdrastiaDataStreamsUpdater.FeedIdAndAddress[] memory feedAddresses = updater.getFeedMapping();

        // Assert that the feed is registered
        assertTrue(updater.feedExists(ETH_USD_V3.feedId), "Feed should be registered after successful registration");
        assertEq(
            updater.getFeed(ETH_USD_V3.feedId),
            address(ethUsdV3Feed),
            "Feed address should match the registered feed address"
        );
        assertEq(updater.getFeedCount(), 1, "Feed count should be 1 after registration");
        assertEq(feedIds.length, 1, "Feed IDs length should be 1 after registration");
        assertEq(feedAddresses.length, 1, "Feed addresses length should be 1 after registration");
        assertEq(feedIds[0], ETH_USD_V3.feedId, "Feed ID should match the registered feed ID");
        assertEq(feedAddresses[0].feedId, ETH_USD_V3.feedId, "Feed address ID should match the registered feed ID");
        assertEq(feedAddresses[0].feed, address(ethUsdV3Feed), "Feed address should match the registered feed address");
    }

    function test_changeFeed_revertsWhenNotConfigAdmin() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        address unauthorizedUser = address(0x789);
        vm.startPrank(unauthorizedUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                requiredRole
            )
        );
        updater.changeFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed2));
    }

    function test_changeFeed_revertsWhenFeedIdMismatch() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        vm.expectRevert(
            abi.encodeWithSelector(
                AdrastiaDataStreamsUpdater.FeedMismatch.selector,
                BTC_USD_V3.feedId, // contract feedId
                ETH_USD_V3.feedId // provided feedId
            )
        );
        // Try and change the ETH/USD feed with the BTC/USD feed
        updater.changeFeed(ETH_USD_V3.feedId, address(btcUsdV3Feed));
    }

    function test_changeFeed_revertsWhenNotRegistered() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        vm.expectRevert(
            abi.encodeWithSelector(AdrastiaDataStreamsUpdater.FeedNotRegistered.selector, ETH_USD_V3.feedId)
        );
        // Try to change a feed that is not registered
        updater.changeFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed2));
    }

    function test_changeFeed_revertsWhenFeedNotChanged() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        vm.expectRevert(
            abi.encodeWithSelector(
                AdrastiaDataStreamsUpdater.FeedNotChanged.selector,
                ETH_USD_V3.feedId,
                address(ethUsdV3Feed)
            )
        );
        // Try to change the feed to the same address
        updater.changeFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
    }

    function test_changeFeed_worksWithOneFeed() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedTargetChanged(
            ETH_USD_V3.feedId,
            address(ethUsdV3Feed),
            address(ethUsdV3Feed2),
            block.timestamp
        );

        // Change the feed
        updater.changeFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed2));

        bytes32[] memory feedIds = updater.getFeedIds();
        AdrastiaDataStreamsUpdater.FeedIdAndAddress[] memory feedAddresses = updater.getFeedMapping();

        // Assert that the feed is still registered
        assertTrue(updater.feedExists(ETH_USD_V3.feedId), "Feed should be registered after successful change");
        assertEq(
            updater.getFeed(ETH_USD_V3.feedId),
            address(ethUsdV3Feed2),
            "Feed address should match the registered feed address after change"
        );
        assertEq(updater.getFeedCount(), 1, "Feed count should be 1 after change");
        assertEq(feedIds.length, 1, "Feed IDs length should be 1 after change");
        assertEq(feedAddresses.length, 1, "Feed addresses length should be 1 after change");
        assertEq(feedIds[0], ETH_USD_V3.feedId, "Feed ID should match the registered feed ID");
        assertEq(feedAddresses[0].feedId, ETH_USD_V3.feedId, "Feed address ID should match the registered feed ID");
        assertEq(feedAddresses[0].feed, address(ethUsdV3Feed2), "Feed address should match the changed feed address");
    }

    function test_changeFeed_onlyChangesTheSpecifiedFeed_firstFeed() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feeds first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
        updater.registerFeed(BTC_USD_V3.feedId, address(btcUsdV3Feed));

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedTargetChanged(
            ETH_USD_V3.feedId,
            address(ethUsdV3Feed),
            address(ethUsdV3Feed2),
            block.timestamp
        );

        // Change the ETH/USD feed
        updater.changeFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed2));

        bytes32[] memory feedIds = updater.getFeedIds();
        AdrastiaDataStreamsUpdater.FeedIdAndAddress[] memory feedAddresses = updater.getFeedMapping();

        // Assert that the ETH/USD feed is changed
        assertTrue(updater.feedExists(ETH_USD_V3.feedId), "ETH/USD feed should be registered after change");
        assertEq(
            updater.getFeed(ETH_USD_V3.feedId),
            address(ethUsdV3Feed2),
            "ETH/USD feed address should match the changed ETH/USD feed address"
        );
        assertEq(updater.getFeedCount(), 2, "Feed count should be 2 after change");
        assertEq(feedIds.length, 2, "Feed IDs length should be 2 after change");
        assertEq(feedAddresses.length, 2, "Feed addresses length should be 2 after change");

        // Assert the ETH/USD feed details
        assertEq(feedIds[0], ETH_USD_V3.feedId, "First feed ID should match the registered ETH/USD feed ID");
        assertEq(
            feedAddresses[0].feedId,
            ETH_USD_V3.feedId,
            "First feed address ID should match the registered ETH/USD feed ID"
        );
        assertEq(
            feedAddresses[0].feed,
            address(ethUsdV3Feed2),
            "First feed address should match the changed ETH/USD feed address"
        );

        // Assert the BTC/USD feed details remain unchanged
        assertTrue(updater.feedExists(BTC_USD_V3.feedId), "BTC/USD feed should still be registered");
        assertEq(
            updater.getFeed(BTC_USD_V3.feedId),
            address(btcUsdV3Feed),
            "BTC/USD feed address should match the registered BTC/USD feed address"
        );
        assertEq(feedIds[1], BTC_USD_V3.feedId, "Second feed ID should match the registered BTC/USD feed ID");
        assertEq(
            feedAddresses[1].feedId,
            BTC_USD_V3.feedId,
            "Second feed address ID should match the registered BTC/USD feed ID"
        );
        assertEq(
            feedAddresses[1].feed,
            address(btcUsdV3Feed),
            "Second feed address should match the registered BTC/USD feed address"
        );
    }

    function test_changeFeed_onlyChangesTheSpecifiedFeed_secondFeed() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feeds first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
        updater.registerFeed(BTC_USD_V3.feedId, address(btcUsdV3Feed));

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedTargetChanged(
            BTC_USD_V3.feedId,
            address(btcUsdV3Feed),
            address(btcUsdV3Feed2),
            block.timestamp
        );

        // Change the BTC/USD feed
        updater.changeFeed(BTC_USD_V3.feedId, address(btcUsdV3Feed2));

        bytes32[] memory feedIds = updater.getFeedIds();
        AdrastiaDataStreamsUpdater.FeedIdAndAddress[] memory feedAddresses = updater.getFeedMapping();

        // Assert that the BTC/USD feed is changed
        assertTrue(updater.feedExists(BTC_USD_V3.feedId), "BTC/USD feed should be registered after change");
        assertEq(
            updater.getFeed(BTC_USD_V3.feedId),
            address(btcUsdV3Feed2),
            "BTC/USD feed address should match the changed BTC/USD feed address"
        );
        assertEq(updater.getFeedCount(), 2, "Feed count should be 2 after change");
        assertEq(feedIds.length, 2, "Feed IDs length should be 2 after change");
        assertEq(feedAddresses.length, 2, "Feed addresses length should be 2 after change");

        // Assert the ETH/USD feed details remain unchanged
        assertTrue(updater.feedExists(ETH_USD_V3.feedId), "ETH/USD feed should still be registered");
        assertEq(
            updater.getFeed(ETH_USD_V3.feedId),
            address(ethUsdV3Feed),
            "ETH/USD feed address should match the registered ETH/USD feed address"
        );
        assertEq(feedIds[0], ETH_USD_V3.feedId, "First feed ID should match the registered ETH/USD feed ID");
        assertEq(
            feedAddresses[0].feedId,
            ETH_USD_V3.feedId,
            "First feed address ID should match the registered ETH/USD feed ID"
        );
        assertEq(
            feedAddresses[0].feed,
            address(ethUsdV3Feed),
            "First feed address should match the registered ETH/USD feed address"
        );

        // Assert the BTC/USD feed details
        assertEq(feedIds[1], BTC_USD_V3.feedId, "Second feed ID should match the registered BTC/USD feed ID");
        assertEq(
            feedAddresses[1].feedId,
            BTC_USD_V3.feedId,
            "Second feed address ID should match the registered BTC/USD feed ID"
        );
        assertEq(
            feedAddresses[1].feed,
            address(btcUsdV3Feed2),
            "Second feed address should match the changed BTC/USD feed address"
        );
    }

    function test_unregisterFeed_revertsWhenNotConfigAdmin() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        address unauthorizedUser = address(0x789);
        vm.startPrank(unauthorizedUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                requiredRole
            )
        );
        updater.unregisterFeed(ETH_USD_V3.feedId);
    }

    function test_unregisterFeed_revertsWhenNotRegistered() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        vm.expectRevert(
            abi.encodeWithSelector(AdrastiaDataStreamsUpdater.FeedNotRegistered.selector, ETH_USD_V3.feedId)
        );
        // Try to unregister a feed that is not registered
        updater.unregisterFeed(ETH_USD_V3.feedId);
    }

    function test_unregisterFeed_unregistersOneFeed() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedTargetChanged(
            ETH_USD_V3.feedId,
            address(ethUsdV3Feed),
            address(0),
            block.timestamp
        );

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedRegistrationChanged(
            ETH_USD_V3.feedId,
            AdrastiaDataStreamsUpdater.FeedRegistrationAction.UNREGISTER,
            block.timestamp
        );

        // Unregister the feed
        updater.unregisterFeed(ETH_USD_V3.feedId);

        bytes32[] memory feedIds = updater.getFeedIds();
        AdrastiaDataStreamsUpdater.FeedIdAndAddress[] memory feedAddresses = updater.getFeedMapping();

        // Assert that the feed is unregistered
        assertFalse(
            updater.feedExists(ETH_USD_V3.feedId),
            "Feed should be unregistered after successful unregistration"
        );
        assertEq(updater.getFeedCount(), 0, "Feed count should be 0 after unregistration");
        assertEq(feedIds.length, 0, "Feed IDs length should be 0 after unregistration");
        assertEq(feedAddresses.length, 0, "Feed addresses length should be 0 after unregistration");

        vm.expectRevert(
            abi.encodeWithSelector(AdrastiaDataStreamsUpdater.FeedNotRegistered.selector, ETH_USD_V3.feedId)
        );
        // Assert that the feed is not registered anymore
        updater.getFeed(ETH_USD_V3.feedId);
    }

    function test_unregisterFeed_onlyUnregistersTheSpecifiedFeed_firstFeed() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feeds first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
        updater.registerFeed(BTC_USD_V3.feedId, address(btcUsdV3Feed));

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedTargetChanged(
            ETH_USD_V3.feedId,
            address(ethUsdV3Feed),
            address(0),
            block.timestamp
        );

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedRegistrationChanged(
            ETH_USD_V3.feedId,
            AdrastiaDataStreamsUpdater.FeedRegistrationAction.UNREGISTER,
            block.timestamp
        );

        // Unregister the ETH/USD feed
        updater.unregisterFeed(ETH_USD_V3.feedId);

        bytes32[] memory feedIds = updater.getFeedIds();
        AdrastiaDataStreamsUpdater.FeedIdAndAddress[] memory feedAddresses = updater.getFeedMapping();

        // Assert that the ETH/USD feed is unregistered
        assertFalse(updater.feedExists(ETH_USD_V3.feedId), "ETH/USD feed should be unregistered after unregistration");
        assertEq(updater.getFeedCount(), 1, "Feed count should be 1 after unregistering one feed");
        assertEq(feedIds.length, 1, "Feed IDs length should be 1 after unregistering one feed");
        assertEq(feedAddresses.length, 1, "Feed addresses length should be 1 after unregistering one feed");

        vm.expectRevert(
            abi.encodeWithSelector(AdrastiaDataStreamsUpdater.FeedNotRegistered.selector, ETH_USD_V3.feedId)
        );
        // Assert that the feed is not registered anymore
        updater.getFeed(ETH_USD_V3.feedId);

        // Assert the BTC/USD feed details remain unchanged
        assertTrue(updater.feedExists(BTC_USD_V3.feedId), "BTC/USD feed should still be registered");
        assertEq(
            updater.getFeed(BTC_USD_V3.feedId),
            address(btcUsdV3Feed),
            "BTC/USD feed address should match the registered BTC/USD feed address"
        );
        assertEq(feedIds[0], BTC_USD_V3.feedId, "First feed ID should match the registered BTC/USD feed ID");
        assertEq(
            feedAddresses[0].feedId,
            BTC_USD_V3.feedId,
            "First feed address ID should match the registered BTC/USD feed ID"
        );
        assertEq(
            feedAddresses[0].feed,
            address(btcUsdV3Feed),
            "First feed address should match the registered BTC/USD feed address"
        );
    }

    function test_unregisterFeed_onlyUnregistersTheSpecifiedFeed_secondFeed() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feeds first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
        updater.registerFeed(BTC_USD_V3.feedId, address(btcUsdV3Feed));

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedTargetChanged(
            BTC_USD_V3.feedId,
            address(btcUsdV3Feed),
            address(0),
            block.timestamp
        );

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedRegistrationChanged(
            BTC_USD_V3.feedId,
            AdrastiaDataStreamsUpdater.FeedRegistrationAction.UNREGISTER,
            block.timestamp
        );

        // Unregister the BTC/USD feed
        updater.unregisterFeed(BTC_USD_V3.feedId);

        bytes32[] memory feedIds = updater.getFeedIds();
        AdrastiaDataStreamsUpdater.FeedIdAndAddress[] memory feedAddresses = updater.getFeedMapping();

        // Assert that the BTC/USD feed is unregistered
        assertFalse(updater.feedExists(BTC_USD_V3.feedId), "BTC/USD feed should be unregistered after unregistration");
        assertEq(updater.getFeedCount(), 1, "Feed count should be 1 after unregistering one feed");
        assertEq(feedIds.length, 1, "Feed IDs length should be 1 after unregistering one feed");
        assertEq(feedAddresses.length, 1, "Feed addresses length should be 1 after unregistering one feed");

        vm.expectRevert(
            abi.encodeWithSelector(AdrastiaDataStreamsUpdater.FeedNotRegistered.selector, BTC_USD_V3.feedId)
        );
        // Assert that the feed is not registered anymore
        updater.getFeed(BTC_USD_V3.feedId);

        // Assert the ETH/USD feed details remain unchanged
        assertTrue(updater.feedExists(ETH_USD_V3.feedId), "ETH/USD feed should still be registered");
        assertEq(
            updater.getFeed(ETH_USD_V3.feedId),
            address(ethUsdV3Feed),
            "ETH/USD feed address should match the registered ETH/USD feed address"
        );
        assertEq(feedIds[0], ETH_USD_V3.feedId, "First feed ID should match the registered ETH/USD feed ID");
        assertEq(
            feedAddresses[0].feedId,
            ETH_USD_V3.feedId,
            "First feed address ID should match the registered ETH/USD feed ID"
        );
        assertEq(
            feedAddresses[0].feed,
            address(ethUsdV3Feed),
            "First feed address should match the registered ETH/USD feed address"
        );
    }

    function test_withdrawErc20_revertsWhenNotAdmin() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.ADMIN();
        address unauthorizedUser = address(0x789);
        vm.startPrank(unauthorizedUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                requiredRole
            )
        );
        updater.withdrawErc20(address(0x123), unauthorizedUser, 100);
    }

    function test_withdrawErc20_revertsWhenMoreThanBalance() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );
        FakeErc20 fakeErc20 = new FakeErc20();

        // Send some tokens to the feed contract
        uint256 amount = 1 * 10 ** fakeErc20.decimals();
        fakeErc20.transfer(address(updater), amount);

        address recipient = address(0x123);

        // Attempt to withdraw more than the balance
        vm.expectRevert();
        updater.withdrawErc20(address(fakeErc20), recipient, amount + 1);
    }

    function test_withdrawErc20_adminCanWithdraw() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );
        FakeErc20 fakeErc20 = new FakeErc20();

        // Send some tokens to the feed contract
        uint256 amount = 1 * 10 ** fakeErc20.decimals();
        fakeErc20.transfer(address(updater), amount);

        address recipient = address(0x123);

        // Withdraw the tokens
        updater.withdrawErc20(address(fakeErc20), recipient, amount);

        assertEq(fakeErc20.balanceOf(recipient), amount, "Recipient should have received the withdrawn tokens");
    }

    function test_withdrawNative_revertsWhenNotAdmin() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.ADMIN();
        address unauthorizedUser = address(0x789);
        vm.startPrank(unauthorizedUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                requiredRole
            )
        );
        updater.withdrawNative(unauthorizedUser, 100);
    }

    function test_withdrawNative_revertsWhenMoreThanBalance() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        // Attempt to withdraw more than the balance
        vm.expectRevert();
        updater.withdrawNative(address(0x123), 1 ether);
    }

    function test_withdrawNative_adminCanWithdraw() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        address recipient = address(0x123);

        // Send some native tokens to the updater contract
        vm.deal(address(updater), 1 ether);

        // Check the balance before withdrawal
        assertEq(address(updater).balance, 1 ether, "Updater contract should have 1 ether before withdrawal");

        // Withdraw some native tokens
        updater.withdrawNative(recipient, 1 ether);

        assertEq(address(recipient).balance, 1 ether, "Recipient should have received the withdrawn native tokens");
        assertEq(address(updater).balance, 0, "Updater contract should have 0 ether after withdrawal");
    }

    function test_approveVerifierFeeSpend_noOpWhenNoRewardManager() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        FeeManagerStub feeManagerStub = new FeeManagerStub();

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        // Approve the verifier fee spend with no reward manager
        updater.approveVerifierFeeSpend();
    }

    function test_approveVerifierFeeSpend_noOpWhenNoRewardToken() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        FeeManagerStub feeManagerStub = new FeeManagerStub();

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        // Set a reward manager but no reward token
        feeManagerStub.setRewardManager(address(0x123));

        // Approve the verifier fee spend with no reward token
        updater.approveVerifierFeeSpend();
    }

    function test_approveVerifierFeeSpend_grantsMaxAllowance() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        FeeManagerStub feeManagerStub = new FeeManagerStub();
        RewardManagerStub rewardManagerStub = new RewardManagerStub();
        FakeErc20 fakeLink = new FakeErc20();

        feeManagerStub.setLinkAddress(address(fakeLink));
        feeManagerStub.setRewardManager(address(rewardManagerStub));

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        vm.expectEmit({emitter: address(fakeLink)});
        emit IERC20.Approval(address(updater), address(rewardManagerStub), type(uint256).max);

        // Approve the verifier fee spend
        updater.approveVerifierFeeSpend();

        // Check the allowance
        uint256 allowance = fakeLink.allowance(address(updater), address(rewardManagerStub));
        assertEq(allowance, type(uint256).max, "Allowance should be set to max");
    }

    function test_approveVerifierFeeSpend_secondCallIsNoOp() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        FeeManagerStub feeManagerStub = new FeeManagerStub();
        RewardManagerStub rewardManagerStub = new RewardManagerStub();
        FakeErc20 fakeLink = new FakeErc20();

        feeManagerStub.setLinkAddress(address(fakeLink));
        feeManagerStub.setRewardManager(address(rewardManagerStub));

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        // Approve the verifier fee spend first time
        updater.approveVerifierFeeSpend();

        // Approve the verifier fee spend again
        updater.approveVerifierFeeSpend();

        // Get recorded logs
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Assert that no events were emitted
        assertEq(logs.length, 0, "Expected no events, but some were emitted");
    }

    function test_checkUpkeep_revertsWhenMissingFeedData() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        vm.expectRevert("Missing feed data.");
        // Check upkeep without setting feed data
        updater.checkUpkeep(hex"");
    }

    function test_checkUpkeep_revertsWhenMissingOffchainPrice() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = 1;
        uint256 heartbeat = 1;

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat);

        vm.expectRevert("Missing offchain price.");
        // Check upkeep without setting offchain prices
        updater.checkUpkeep(data);
    }

    function test_checkUpkeep_revertsWhenMissingOffchainTimestamp() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = 1;
        uint256 heartbeat = 1;
        int256 offchainPrice = 2000 * 10 ** 18; // Example price in 18 decimals

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice);

        vm.expectRevert("Missing offchain timestamp.");
        // Check upkeep without setting offchain timestamps
        updater.checkUpkeep(data);
    }

    function test_checkUpkeep_revertsWhenTooMuchData() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = 1;
        uint256 heartbeat = 1;
        int256 offchainPrice = 2000 * 10 ** 18; // Example price in 18 decimals
        uint256 offchainTimestamp = block.timestamp;

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        // Create data with too many parameters
        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice, offchainTimestamp, "extra");

        vm.expectRevert("Too much data.");
        // Check upkeep with too much data
        updater.checkUpkeep(data);
    }

    function test_checkUpkeep_revertsWhenFeedNotRegistered() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = 1;
        uint256 heartbeat = 1;
        int256 offchainPrice = 2000 * 10 ** 18; // Example price in 18 decimals
        uint256 offchainTimestamp = block.timestamp;

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice, offchainTimestamp);

        vm.expectRevert(abi.encodeWithSelector(AdrastiaDataStreamsUpdater.FeedNotRegistered.selector, feedId));
        // Check upkeep for a feed that is not registered
        updater.checkUpkeep(data);
    }

    function test_checkUpkeep_worksWhenTheFeedDoesntHaveAnyData() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = 1;
        uint256 heartbeat = 1;
        int256 offchainPrice = 2000 * 10 ** 18; // Example price in 18 decimals
        uint256 offchainTimestamp = block.timestamp;

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice, offchainTimestamp);

        // Check upkeep for a feed that doesn't have any data
        (bool upkeepRequired, bytes memory performData) = updater.checkUpkeep(data);
        assertTrue(upkeepRequired);

        (int256 feedPrice, uint256 feedTimestamp, bool heartbeatTriggered, bool priceDeviationTriggered) = abi.decode(
            performData,
            (int256, uint256, bool, bool)
        );

        // Price should be 0 since no data was set
        assertEq(feedPrice, 0, "Feed price should be 0 when no data is set");
        assertEq(feedTimestamp, 0, "Feed timestamp should be 0 when no data is set");

        // Heartbeat and price deviation should be triggered
        assertTrue(heartbeatTriggered, "Heartbeat should be triggered when no data is set");
        assertTrue(priceDeviationTriggered, "Price deviation should be triggered when no data is set");
    }

    function test_checkUpkeep_returnsTrueWhenAHeartbeatIsNeeded() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = DEFAULT_UPDATE_THRESHOLD;
        uint32 heartbeat = DEFAULT_HEARTBEAT;

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        // Set the offchain price and timestamp to trigger a heartbeat
        int192 offchainPrice = 2000 * 10 ** 18; // Example price in 18 decimals
        uint32 offchainTimestamp = uint32(block.timestamp);

        int192 fakeOnchainPrice = offchainPrice; // No change
        uint32 fakeOnchainTimestamp = offchainTimestamp - heartbeat; // Simulate a heartbeat needed

        ethUsdV3Feed.stubPush(
            fakeOnchainPrice,
            fakeOnchainTimestamp,
            offchainTimestamp + 1000 // expiresAt
        );

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice, offchainTimestamp);

        // Check upkeep for a feed that needs a heartbeat
        (bool upkeepRequired, bytes memory performData) = updater.checkUpkeep(data);

        (int256 feedPrice, uint256 feedTimestamp, bool heartbeatTriggered, bool priceDeviationTriggered) = abi.decode(
            performData,
            (int256, uint256, bool, bool)
        );

        // Price should be the offchain price set
        assertEq(feedPrice, fakeOnchainPrice, "Feed price should match the what we set");
        assertEq(feedTimestamp, fakeOnchainTimestamp, "Feed timestamp should match the what we set");

        // Heartbeat should be triggered
        assertTrue(heartbeatTriggered, "Heartbeat should be triggered when needed");
        assertFalse(priceDeviationTriggered, "Price deviation should not be triggered when only heartbeat is needed");

        assertTrue(upkeepRequired, "Upkeep should be required when a heartbeat is needed");
    }

    function test_checkUpkeep_returnsTrueWhenUpdateThresholdSurpassed() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = 1; // Set a low threshold to trigger quickly
        uint32 heartbeat = DEFAULT_HEARTBEAT;

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        // Set the offchain price and timestamp to trigger an update
        int192 offchainPrice = 2000 * 10 ** 18; // Example price in 18 decimals
        uint32 offchainTimestamp = uint32(block.timestamp);

        int192 fakeOnchainPrice = 1900 * 10 ** 18; // Simulate a price change
        uint32 fakeOnchainTimestamp = offchainTimestamp - heartbeat + 1; // Will not trigger heartbeat

        ethUsdV3Feed.stubPush(
            fakeOnchainPrice,
            fakeOnchainTimestamp,
            offchainTimestamp + 1000 // expiresAt
        );

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice, offchainTimestamp);

        // Check upkeep for a feed that needs an update due to threshold surpassing
        (bool upkeepRequired, bytes memory performData) = updater.checkUpkeep(data);

        (int256 feedPrice, uint256 feedTimestamp, bool heartbeatTriggered, bool priceDeviationTriggered) = abi.decode(
            performData,
            (int256, uint256, bool, bool)
        );

        // Price should be the onchain price set
        assertEq(feedPrice, fakeOnchainPrice, "Feed price should match the what we set");
        assertEq(feedTimestamp, fakeOnchainTimestamp, "Feed timestamp should match the what we set");

        // Heartbeat should not be triggered since we have a valid onchain price
        assertFalse(heartbeatTriggered, "Heartbeat should not be triggered when an update is needed");
        assertTrue(priceDeviationTriggered, "Price deviation should be triggered when update threshold is surpassed");

        assertTrue(upkeepRequired, "Upkeep should be required when update threshold is surpassed");
    }

    function test_checkUpkeep_returnsTrueWhenBothHeartbeatAndUpdateThresholdSurpassed() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = 1; // Set a low threshold to trigger quickly
        uint32 heartbeat = DEFAULT_HEARTBEAT;

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        // Set the offchain price and timestamp to trigger both heartbeat and update threshold
        int192 offchainPrice = 2000 * 10 ** 18; // Example price in 18 decimals
        uint32 offchainTimestamp = uint32(block.timestamp);

        int192 fakeOnchainPrice = 1800 * 10 ** 18; // Simulate a price change
        uint32 fakeOnchainTimestamp = offchainTimestamp - heartbeat - 1; // Will trigger heartbeat

        ethUsdV3Feed.stubPush(
            fakeOnchainPrice,
            fakeOnchainTimestamp,
            offchainTimestamp + 1000 // expiresAt
        );

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice, offchainTimestamp);

        // Check upkeep for a feed that needs both heartbeat and update due to threshold surpassing
        (bool upkeepRequired, bytes memory performData) = updater.checkUpkeep(data);

        (int256 feedPrice, uint256 feedTimestamp, bool heartbeatTriggered, bool priceDeviationTriggered) = abi.decode(
            performData,
            (int256, uint256, bool, bool)
        );

        // Price should be the onchain price set
        assertEq(feedPrice, fakeOnchainPrice, "Feed price should match the what we set");
        assertEq(feedTimestamp, fakeOnchainTimestamp, "Feed timestamp should match the what we set");

        // Both heartbeat and price deviation should be triggered
        assertTrue(heartbeatTriggered, "Heartbeat should be triggered when needed");
        assertTrue(priceDeviationTriggered, "Price deviation should be triggered when update threshold is surpassed");

        assertTrue(upkeepRequired, "Upkeep should be required when both heartbeat and update threshold are surpassed");
    }

    function test_checkUpkeep_worksIfPriceIsZeroToZero() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = DEFAULT_UPDATE_THRESHOLD;
        uint32 heartbeat = DEFAULT_HEARTBEAT;

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        // Set the offchain price and timestamp to trigger an update
        int192 offchainPrice = 0; // Example price in 18 decimals
        uint32 offchainTimestamp = uint32(block.timestamp);

        int192 fakeOnchainPrice = 0; // Simulate a price change
        uint32 fakeOnchainTimestamp = offchainTimestamp - heartbeat - 1; // Will trigger heartbeat

        ethUsdV3Feed.stubPush(
            fakeOnchainPrice,
            fakeOnchainTimestamp,
            offchainTimestamp + 1000 // expiresAt
        );

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice, offchainTimestamp);

        // Check upkeep for a feed that needs an update due to threshold surpassing
        (bool upkeepRequired, bytes memory performData) = updater.checkUpkeep(data);

        (int256 feedPrice, uint256 feedTimestamp, bool heartbeatTriggered, bool priceDeviationTriggered) = abi.decode(
            performData,
            (int256, uint256, bool, bool)
        );

        // Price should be the onchain price set
        assertEq(feedPrice, fakeOnchainPrice, "Feed price should match the what we set");
        assertEq(feedTimestamp, fakeOnchainTimestamp, "Feed timestamp should match the what we set");

        // Heartbeat should not be triggered since we have a valid onchain price
        assertTrue(heartbeatTriggered, "Heartbeat should be triggered");
        assertFalse(priceDeviationTriggered, "Price deviation should not be triggered as price is zero to zero");

        assertTrue(upkeepRequired, "Upkeep should be required");
    }

    function test_checkUpkeep_posToNegTriggersUpdateThreshold() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = 10 ** 8; // 100% (8 decimals)
        uint32 heartbeat = DEFAULT_HEARTBEAT;

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        // Set the offchain price and timestamp to trigger an update
        int192 offchainPrice = -1; // Example price in 18 decimals
        uint32 offchainTimestamp = uint32(block.timestamp);

        int192 fakeOnchainPrice = 1; // Simulate a price change from negative to positive
        uint32 fakeOnchainTimestamp = offchainTimestamp - heartbeat + 1; // Will not trigger heartbeat

        ethUsdV3Feed.stubPush(
            fakeOnchainPrice,
            fakeOnchainTimestamp,
            offchainTimestamp + 1000 // expiresAt
        );

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice, offchainTimestamp);

        // Check upkeep for a feed that needs an update due to threshold surpassing
        (bool upkeepRequired, bytes memory performData) = updater.checkUpkeep(data);

        (int256 feedPrice, uint256 feedTimestamp, bool heartbeatTriggered, bool priceDeviationTriggered) = abi.decode(
            performData,
            (int256, uint256, bool, bool)
        );

        // Price should be the onchain price set
        assertEq(feedPrice, fakeOnchainPrice, "Feed price should match the what we set");
        assertEq(feedTimestamp, fakeOnchainTimestamp, "Feed timestamp should match the what we set");

        // Heartbeat should not be triggered since we have a valid onchain price
        assertFalse(heartbeatTriggered, "Heartbeat should not be triggered");
        assertTrue(priceDeviationTriggered, "Price deviation should be triggered");

        assertTrue(upkeepRequired, "Upkeep should be required when update threshold is surpassed");
    }

    function test_checkUpkeep_negToPosTriggersUpdateThreshold() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = 10 ** 8; // 100% (8 decimals)
        uint32 heartbeat = DEFAULT_HEARTBEAT;

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        // Set the offchain price and timestamp to trigger an update
        int192 offchainPrice = 1; // Example price in 18 decimals
        uint32 offchainTimestamp = uint32(block.timestamp);

        int192 fakeOnchainPrice = -1; // Simulate a price change from positive to negative
        uint32 fakeOnchainTimestamp = offchainTimestamp - heartbeat + 1; // Will not trigger heartbeat

        ethUsdV3Feed.stubPush(
            fakeOnchainPrice,
            fakeOnchainTimestamp,
            offchainTimestamp + 1000 // expiresAt
        );

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice, offchainTimestamp);

        // Check upkeep for a feed that needs an update due to threshold surpassing
        (bool upkeepRequired, bytes memory performData) = updater.checkUpkeep(data);

        (int256 feedPrice, uint256 feedTimestamp, bool heartbeatTriggered, bool priceDeviationTriggered) = abi.decode(
            performData,
            (int256, uint256, bool, bool)
        );

        // Price should be the onchain price set
        assertEq(feedPrice, fakeOnchainPrice, "Feed price should match the what we set");
        assertEq(feedTimestamp, fakeOnchainTimestamp, "Feed timestamp should match the what we set");

        // Heartbeat should not be triggered since we have a valid onchain price
        assertFalse(heartbeatTriggered, "Heartbeat should not be triggered");
        assertTrue(priceDeviationTriggered, "Price deviation should be triggere");

        assertTrue(upkeepRequired, "Upkeep should be required when update threshold is surpassed");
    }

    function test_checkUpkeep_worksWithTheLargestChangeInPrice() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.CONFIG_ADMIN();
        updater.grantRole(requiredRole, address(this));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint256 updateThreshold = 10 ** 8; // 100% (8 decimals)
        uint32 heartbeat = DEFAULT_HEARTBEAT;

        // Register the feed first
        updater.registerFeed(feedId, address(ethUsdV3Feed));

        // Set the offchain price and timestamp to trigger an update
        int192 offchainPrice = type(int192).min; // Example price in 18 decimals
        uint32 offchainTimestamp = uint32(block.timestamp);

        int192 fakeOnchainPrice = type(int192).max; // Simulate the largest possible price change
        uint32 fakeOnchainTimestamp = offchainTimestamp - heartbeat + 1; // Will not trigger heartbeat

        ethUsdV3Feed.stubPush(
            fakeOnchainPrice,
            fakeOnchainTimestamp,
            offchainTimestamp + 1000 // expiresAt
        );

        bytes memory data = abi.encode(feedId, updateThreshold, heartbeat, offchainPrice, offchainTimestamp);

        // Check upkeep for a feed that needs an update due to threshold surpassing
        (bool upkeepRequired, bytes memory performData) = updater.checkUpkeep(data);

        (int256 feedPrice, uint256 feedTimestamp, bool heartbeatTriggered, bool priceDeviationTriggered) = abi.decode(
            performData,
            (int256, uint256, bool, bool)
        );

        // Price should be the onchain price set
        assertEq(feedPrice, fakeOnchainPrice, "Feed price should match the what we set");
        assertEq(feedTimestamp, fakeOnchainTimestamp, "Feed timestamp should match the what we set");

        // Heartbeat should not be triggered since we have a valid onchain price
        assertFalse(heartbeatTriggered, "Heartbeat should not be triggered");
        assertTrue(priceDeviationTriggered, "Price deviation should be triggered");

        assertTrue(upkeepRequired, "Upkeep should be required when update threshold is surpassed");
    }

    function test_performUpkeep_revertsWhenNotOracleUpdater() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 requiredRole = updater.ORACLE_UPDATER();
        address unauthorizedUser = address(0x789);
        vm.startPrank(unauthorizedUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                requiredRole
            )
        );
        updater.performUpkeep(hex"");
    }

    function test_performUpkeep_revertsWhenReportLengthMismatch() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        bytes[] memory reports = new bytes[](1);
        reports[0] = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory performData = abi.encode(reports);

        bytes[] memory signedReports = new bytes[](0);

        verifierStub.stubOverrideVerifyBulk(true, signedReports);

        vm.expectRevert(
            abi.encodeWithSelector(
                AdrastiaDataStreamsUpdater.ReportLengthMismatch.selector,
                reports.length,
                signedReports.length
            )
        );
        updater.performUpkeep(performData);
    }

    function test_performUpkeep_revertsWhenNoReportsProvided() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        bytes[] memory reports = new bytes[](0);
        bytes memory performData = abi.encode(reports);

        vm.expectRevert(abi.encodeWithSelector(AdrastiaDataStreamsUpdater.NoReportsProvided.selector));
        // Perform upkeep with no reports
        updater.performUpkeep(performData);
    }

    function test_performUpkeep_revertsWhenFeedNotRegistered() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes[] memory reports = new bytes[](1);
        reports[0] = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory performData = abi.encode(reports);

        vm.expectRevert(
            abi.encodeWithSelector(AdrastiaDataStreamsUpdater.FeedNotRegistered.selector, ETH_USD_V3.feedId)
        );
        // Perform upkeep for a feed that is not registered
        updater.performUpkeep(performData);
    }

    function test_performUpkeep_revertsWhenOneOfTwoFeedsIsNotRegistered() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes32 reportVerifierRole = ethUsdV3Feed.REPORT_VERIFIER();
        ethUsdV3Feed.grantRole(reportVerifierRole, address(updater));
        btcUsdV3Feed.grantRole(reportVerifierRole, address(updater));

        // Register the ETH/USD feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        bytes[] memory reports = new bytes[](2);
        reports[0] = generateSimpleReportData(ETH_USD_V3.feedId, true);
        reports[1] = generateSimpleReportData(BTC_USD_V3.feedId, true);

        bytes memory performData = abi.encode(reports);

        vm.expectRevert(
            abi.encodeWithSelector(AdrastiaDataStreamsUpdater.FeedNotRegistered.selector, BTC_USD_V3.feedId)
        );
        // Perform upkeep for a feed that is not registered
        updater.performUpkeep(performData);
    }

    function test_performUpkeep_performsOneUpdate() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes32 reportVerifierRole = ethUsdV3Feed.REPORT_VERIFIER();
        ethUsdV3Feed.grantRole(reportVerifierRole, address(updater));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        int192 ethUsdPrice = 2000 * 10 ** 18; // Example price in 18 decimals

        bytes[] memory reports = new bytes[](1);
        reports[0] = generateSimpleReportDataWithPrice(ETH_USD_V3.feedId, ethUsdPrice, true);

        bytes memory performData = abi.encode(reports);

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedUpdatePerformed(ETH_USD_V3.feedId, address(ethUsdV3Feed), block.timestamp);

        // Perform the upkeep
        updater.performUpkeep(performData);

        // Verify the price was updated
        assertEq(ethUsdV3Feed.latestAnswer(), ethUsdPrice, "ETH/USD feed price should match the report price");
    }

    function test_performUpkeep_performsTwoUpdates() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes32 reportVerifierRole = ethUsdV3Feed.REPORT_VERIFIER();
        ethUsdV3Feed.grantRole(reportVerifierRole, address(updater));
        btcUsdV3Feed.grantRole(reportVerifierRole, address(updater));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
        updater.registerFeed(BTC_USD_V3.feedId, address(btcUsdV3Feed));

        int192 ethUsdPrice = 2000 * 10 ** 18; // Example price in 18 decimals
        int192 btcUsdPrice = 30000 * 10 ** 18; // Example

        bytes[] memory reports = new bytes[](2);
        reports[0] = generateSimpleReportDataWithPrice(ETH_USD_V3.feedId, ethUsdPrice, true);
        reports[1] = generateSimpleReportDataWithPrice(BTC_USD_V3.feedId, btcUsdPrice, true);

        bytes memory performData = abi.encode(reports);

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedUpdatePerformed(ETH_USD_V3.feedId, address(ethUsdV3Feed), block.timestamp);
        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedUpdatePerformed(BTC_USD_V3.feedId, address(btcUsdV3Feed), block.timestamp);

        // Perform the upkeep
        updater.performUpkeep(performData);

        // Verify the prices were updated
        assertEq(ethUsdV3Feed.latestAnswer(), ethUsdPrice, "ETH/USD feed price should match the report price");
        assertEq(btcUsdV3Feed.latestAnswer(), btcUsdPrice, "BTC/USD feed price should match the report price");
    }

    function test_performUpkeep_revertsWhenAllFeedUpdatesAreSkipped_oneFeed() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes32 reportVerifierRole = ethUsdV3Feed.REPORT_VERIFIER();
        ethUsdV3Feed.grantRole(reportVerifierRole, address(updater));

        // Push initial data to the feed with a timestamp the same as what the report will use
        ethUsdV3Feed.stubPush(
            1 * 10 ** 18, // Example price in 18 decimals
            uint32(block.timestamp),
            uint32(block.timestamp + 1000) // expiresAt
        );

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        bytes[] memory reports = new bytes[](1);
        reports[0] = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory performData = abi.encode(reports);

        vm.expectRevert(abi.encodeWithSelector(AdrastiaDataStreamsUpdater.NoFeedsUpdated.selector));

        // Perform the upkeep
        updater.performUpkeep(performData);
    }

    function test_performUpkeep_skipsUpdateWhenReportIsNotMoreFresh() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes32 reportVerifierRole = ethUsdV3Feed.REPORT_VERIFIER();
        ethUsdV3Feed.grantRole(reportVerifierRole, address(updater));
        btcUsdV3Feed.grantRole(reportVerifierRole, address(updater));

        // Push initial data to the feed with a timestamp the same as what the report will use
        uint32 timestamp = uint32(block.timestamp);
        ethUsdV3Feed.stubPush(
            1 * 10 ** 18, // Example price in 18 decimals
            timestamp,
            timestamp + 1000 // expiresAt
        );

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
        updater.registerFeed(BTC_USD_V3.feedId, address(btcUsdV3Feed));

        bytes[] memory reports = new bytes[](2);
        reports[0] = generateReportData(
            ETH_USD_V3.feedId,
            timestamp,
            timestamp,
            timestamp + 1000,
            3000 * 10 ** 18,
            true
        ); // Not fresh
        reports[1] = generateSimpleReportData(BTC_USD_V3.feedId, true); // Fresh (initial update)

        bytes memory performData = abi.encode(reports);

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedUpdateSkipped(
            ETH_USD_V3.feedId,
            address(ethUsdV3Feed),
            timestamp,
            timestamp,
            block.timestamp
        );

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedUpdatePerformed(BTC_USD_V3.feedId, address(btcUsdV3Feed), block.timestamp);

        // Perform the upkeep
        updater.performUpkeep(performData);
    }

    function test_performUpkeep_logsFailedUpdates() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes32 reportVerifierRole = ethUsdV3Feed.REPORT_VERIFIER();
        ethUsdV3Feed.grantRole(reportVerifierRole, address(updater));
        btcUsdV3Feed.grantRole(reportVerifierRole, address(updater));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));
        updater.registerFeed(BTC_USD_V3.feedId, address(btcUsdV3Feed));

        uint32 validFrom2 = uint32(block.timestamp) + 10;

        bytes[] memory reports = new bytes[](2);
        reports[0] = generateSimpleReportData(ETH_USD_V3.feedId, true);
        reports[1] = generateReportData(
            BTC_USD_V3.feedId,
            validFrom2,
            validFrom2,
            uint32(block.timestamp + 1000),
            3000 * 10 ** 18,
            true
        );

        bytes memory revertData = abi.encodeWithSelector(
            DataStreamsFeed.ReportIsNotValidYet.selector,
            validFrom2,
            uint32(block.timestamp)
        );

        bytes memory performData = abi.encode(reports);

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedUpdateFailed(
            BTC_USD_V3.feedId,
            address(btcUsdV3Feed),
            revertData,
            block.timestamp
        );

        // Perform the upkeep
        updater.performUpkeep(performData);
    }

    function test_performUpkeep_revertsIfAllUpdatesFail() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes32 reportVerifierRole = ethUsdV3Feed.REPORT_VERIFIER();
        ethUsdV3Feed.grantRole(reportVerifierRole, address(updater));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        uint32 validFrom2 = uint32(block.timestamp) + 10;

        bytes[] memory reports = new bytes[](1);
        reports[0] = generateReportData(
            ETH_USD_V3.feedId,
            validFrom2,
            validFrom2,
            uint32(block.timestamp + 1000),
            3000 * 10 ** 18,
            true
        );

        bytes memory performData = abi.encode(reports);

        vm.expectRevert(abi.encodeWithSelector(AdrastiaDataStreamsUpdater.NoFeedsUpdated.selector));

        // Perform the upkeep
        updater.performUpkeep(performData);
    }

    function test_performUpkeep_handlesNegativePrice() public {
        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes32 reportVerifierRole = ethUsdV3Feed.REPORT_VERIFIER();
        ethUsdV3Feed.grantRole(reportVerifierRole, address(updater));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        int192 price = -1000 * 10 ** 18; // Example negative price in 18 decimals

        bytes[] memory reports = new bytes[](1);
        reports[0] = generateSimpleReportDataWithPrice(ETH_USD_V3.feedId, price, true);

        bytes memory performData = abi.encode(reports);

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedUpdatePerformed(ETH_USD_V3.feedId, address(ethUsdV3Feed), block.timestamp);

        // Perform the upkeep
        updater.performUpkeep(performData);

        assertEq(ethUsdV3Feed.latestAnswer(), price, "Feed should have updated with the negative price");
    }

    function test_performUpkeep_feesArePaid() public {
        FeeManagerStub feeManagerStub = new FeeManagerStub();
        RewardManagerStub rewardManagerStub = new RewardManagerStub();
        FakeErc20 fakeLink = new FakeErc20();

        feeManagerStub.setLinkAddress(address(fakeLink));
        feeManagerStub.setRewardManager(address(rewardManagerStub));

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        // Transfer some LINK to the updater
        fakeLink.transfer(address(updater), 100 * 10 ** 18); // 100 LINK

        uint256 fee = 10 * 10 ** 18; // 10 LINK

        feeManagerStub.setFee(address(fakeLink), fee); // Set fee to 10 LINK

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes32 reportVerifierRole = ethUsdV3Feed.REPORT_VERIFIER();
        ethUsdV3Feed.grantRole(reportVerifierRole, address(updater));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        int192 ethUsdPrice = 2000 * 10 ** 18; // Example price in 18 decimals

        bytes[] memory reports = new bytes[](1);
        reports[0] = generateSimpleReportDataWithPrice(ETH_USD_V3.feedId, ethUsdPrice, true);

        bytes memory performData = abi.encode(reports);

        uint256 updaterBalanceBefore = fakeLink.balanceOf(address(updater));

        vm.expectEmit(true, true, true, true);
        emit AdrastiaDataStreamsUpdater.FeedUpdatePerformed(ETH_USD_V3.feedId, address(ethUsdV3Feed), block.timestamp);

        // Perform the upkeep
        updater.performUpkeep(performData);

        // Verify the price was updated
        assertEq(ethUsdV3Feed.latestAnswer(), ethUsdPrice, "ETH/USD feed price should match the report price");

        uint256 updaterBalanceAfter = fakeLink.balanceOf(address(updater));

        assertEq(updaterBalanceAfter, updaterBalanceBefore - fee, "Updater should have paid the fee");
    }

    function test_performUpkeep_revertsIfInsufficientFees() public {
        FeeManagerStub feeManagerStub = new FeeManagerStub();
        RewardManagerStub rewardManagerStub = new RewardManagerStub();
        FakeErc20 fakeLink = new FakeErc20();

        feeManagerStub.setLinkAddress(address(fakeLink));
        feeManagerStub.setRewardManager(address(rewardManagerStub));

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            address(verifierStub),
            address(this),
            address(this)
        );

        // Transfer some LINK to the updater
        fakeLink.transfer(address(updater), 5 * 10 ** 18); // 5 LINK

        uint256 fee = 10 * 10 ** 18; // 10 LINK

        feeManagerStub.setFee(address(fakeLink), fee); // Set fee to 10 LINK

        bytes32 oracleUpdaterRole = updater.ORACLE_UPDATER();
        bytes32 configAdminRole = updater.CONFIG_ADMIN();
        updater.grantRole(oracleUpdaterRole, address(this));
        updater.grantRole(configAdminRole, address(this));

        bytes32 reportVerifierRole = ethUsdV3Feed.REPORT_VERIFIER();
        ethUsdV3Feed.grantRole(reportVerifierRole, address(updater));

        // Register the feed first
        updater.registerFeed(ETH_USD_V3.feedId, address(ethUsdV3Feed));

        int192 ethUsdPrice = 2000 * 10 ** 18; // Example price in 18 decimals

        bytes[] memory reports = new bytes[](1);
        reports[0] = generateSimpleReportDataWithPrice(ETH_USD_V3.feedId, ethUsdPrice, true);

        bytes memory performData = abi.encode(reports);

        vm.expectRevert();

        // Perform the upkeep
        updater.performUpkeep(performData);
    }

    function test_calculateChange_worksWithTheLargestPositiveChange() public {
        UpdaterStub updater = new UpdaterStub(address(verifierStub), address(this), address(this));

        (, bool maximalChange) = updater.stubCalculateChange(type(int256).max, 1);

        assertTrue(maximalChange, "Should be maximal change");
    }

    function test_calculateChange_neg10ToNeg20() public {
        UpdaterStub updater = new UpdaterStub(address(verifierStub), address(this), address(this));

        (uint256 change, bool maximalChange) = updater.stubCalculateChange(-10, -20);

        uint256 expectedChange = 50 * 10 ** 6; // 50% change in 8 decimals
        assertEq(change, expectedChange, "Change should be 50%");
        assertFalse(maximalChange, "Should not be maximal change");
    }

    function test_calculateChange_pos10ToPos20() public {
        UpdaterStub updater = new UpdaterStub(address(verifierStub), address(this), address(this));

        (uint256 change, bool maximalChange) = updater.stubCalculateChange(10, 20);

        uint256 expectedChange = 50 * 10 ** 6; // 50% change in 8 decimals
        assertEq(change, expectedChange, "Change should be 50%");
        assertFalse(maximalChange, "Should not be maximal change");
    }

    function test_calculateChange_zeroToOne() public {
        UpdaterStub updater = new UpdaterStub(address(verifierStub), address(this), address(this));

        (, bool maximalChange) = updater.stubCalculateChange(0, 1);

        assertTrue(maximalChange, "Should be maximal change");
    }

    function test_calculateChange_zeroToNegOne() public {
        UpdaterStub updater = new UpdaterStub(address(verifierStub), address(this), address(this));

        (, bool maximalChange) = updater.stubCalculateChange(0, -1);

        assertTrue(maximalChange, "Should be maximal change");
    }
}
