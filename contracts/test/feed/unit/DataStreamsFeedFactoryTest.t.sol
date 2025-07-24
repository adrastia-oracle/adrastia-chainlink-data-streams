// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IAccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/IAccessControlEnumerable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {FeedConstants} from "../../FeedConstants.sol";
import {FeedDataFixture} from "../../FeedDataFixture.sol";
import {DataStreamsFeedFactory} from "../../../feed/DataStreamsFeedFactory.sol";
import {DataStreamsFeed} from "../../../feed/DataStreamsFeed.sol";
import {IVerifierProxy} from "../../../vendor/IVerifierProxy.sol";
import {VerifierStub} from "../../VerifierStub.sol";

contract DataStreamsFeedFactoryTest is Test, FeedConstants, FeedDataFixture {
    IVerifierProxy internal verifierStub;

    function setUp() public {
        vm.warp(1752791789);

        verifierStub = new VerifierStub();
    }

    function test_constructor_deploysCorrectly() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        assertEq(
            address(factory.verifierProxy()),
            address(verifierStub),
            "Factory should have correct verifier proxy address"
        );
    }

    function test_contructor_revertsWhenVerifierProxyIsZero() public {
        vm.expectRevert(DataStreamsFeedFactory.InvalidConstructorArguments.selector);
        new DataStreamsFeedFactory(address(0));
    }

    function test_createFeed_revertsWhenFeedIdIsZero() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        vm.expectRevert();
        factory.createFeed(bytes32(0), 18, "Test Feed");
    }

    function test_createFeed_revertsWhenAdminAddressIsZero() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        vm.expectRevert("Admin address cannot be zero");
        factory.createFeed(ETH_USD_V3.feedId, ETH_USD_V3.decimals, ETH_USD_V3.description, address(0), address(0));
    }

    function test_createFeed_revertsWhenTheFeedAlreadyExists() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        // Create the feed first
        factory.createFeed(ETH_USD_V3.feedId, ETH_USD_V3.decimals, ETH_USD_V3.description);

        // Now try to create it again
        vm.expectRevert("Feed already deployed at computed address");
        factory.createFeed(ETH_USD_V3.feedId, ETH_USD_V3.decimals, ETH_USD_V3.description);
    }

    function test_createFeed_allowsMultipleDeploymentsWithDifferentSalt() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        bytes32 salt1 = hex"1234";
        bytes32 salt2 = hex"5678";

        address feedAddress1 = factory.createFeed(
            salt1,
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description,
            address(this),
            address(0) // no updater
        );

        address feedAddress2 = factory.createFeed(
            salt2,
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description,
            address(this),
            address(0) // no updater
        );

        assertNotEq(feedAddress1, feedAddress2, "Feeds created with different salts should have different addresses");
    }

    function test_createFeed_emitsFeedCreatedEvent() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        address expectedAddress = factory.computeFeedAddress(
            address(this), // creator
            hex"", // no user salt
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeedFactory.FeedCreated(address(this), expectedAddress, ETH_USD_V3.feedId, block.timestamp);

        address feedAddress = factory.createFeed(ETH_USD_V3.feedId, ETH_USD_V3.decimals, ETH_USD_V3.description);

        assertEq(feedAddress, expectedAddress, "Created feed address should match expected address");
    }

    function test_createFeed_roleSetup_noUpdater() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        address feedAddress = factory.createFeed(ETH_USD_V3.feedId, ETH_USD_V3.decimals, ETH_USD_V3.description);

        DataStreamsFeed feed = DataStreamsFeed(feedAddress);

        bytes32 adminRole = feed.ADMIN();
        bytes32 reportVerifierRole = feed.REPORT_VERIFIER();

        assertEq(feed.getRoleMemberCount(adminRole), 1, "There should be one admin role member");
        assertTrue(feed.hasRole(adminRole, address(this)), "We should be the admin");

        assertEq(feed.getRoleMemberCount(reportVerifierRole), 0, "There should be no report verifier role members");
    }

    function test_createFeed_roleSetup_withAddresses_noUpdater() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        address fakeAdmin = address(0x123);
        address noUpdater = address(0);

        address feedAddress = factory.createFeed(
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description,
            fakeAdmin,
            noUpdater
        );

        DataStreamsFeed feed = DataStreamsFeed(feedAddress);

        bytes32 adminRole = feed.ADMIN();
        bytes32 reportVerifierRole = feed.REPORT_VERIFIER();

        assertEq(feed.getRoleMemberCount(adminRole), 1, "There should be one admin role member");
        assertTrue(feed.hasRole(adminRole, fakeAdmin), "The specified admin should be the admin");

        assertEq(feed.getRoleMemberCount(reportVerifierRole), 0, "There should be no report verifier role members");
    }

    function test_createFeed_roleSetup_withAddresses_withUpdater() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        address fakeAdmin = address(0x123);
        address fakeUpdater = address(0x456);

        address feedAddress = factory.createFeed(
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description,
            fakeAdmin,
            fakeUpdater
        );

        DataStreamsFeed feed = DataStreamsFeed(feedAddress);

        bytes32 adminRole = feed.ADMIN();
        bytes32 reportVerifierRole = feed.REPORT_VERIFIER();

        assertEq(feed.getRoleMemberCount(adminRole), 1, "There should be one admin role member");
        assertTrue(feed.hasRole(adminRole, fakeAdmin), "The specified admin should be the admin");

        assertEq(feed.getRoleMemberCount(reportVerifierRole), 1, "There should be one report verifier role member");
        assertTrue(feed.hasRole(reportVerifierRole, fakeUpdater), "The specified updater should have the role");
    }

    function test_computeFeedAddress_predictsCorrectly_withSalt() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint8 decimals = ETH_USD_V3.decimals;
        string memory description = ETH_USD_V3.description;

        bytes32 userSalt = hex"1234";

        address expectedAddress = factory.computeFeedAddress(
            address(this), // creator
            userSalt,
            feedId,
            decimals,
            description
        );

        address actualAddress = factory.createFeed(
            userSalt,
            feedId,
            decimals,
            description,
            address(this),
            address(0) // no updater
        );

        assertEq(expectedAddress, actualAddress, "Computed address should match the created feed address");
    }

    function test_computeFeedAddress_predictsCorrectly_withoutSalt() public {
        DataStreamsFeedFactory factory = new DataStreamsFeedFactory(address(verifierStub));

        bytes32 feedId = ETH_USD_V3.feedId;
        uint8 decimals = ETH_USD_V3.decimals;
        string memory description = ETH_USD_V3.description;

        address expectedAddress = factory.computeFeedAddress(
            address(this), // creator
            hex"", // no user salt
            feedId,
            decimals,
            description
        );

        address actualAddress = factory.createFeed(
            feedId,
            decimals,
            description,
            address(this),
            address(0) // no updater
        );

        assertEq(expectedAddress, actualAddress, "Computed address should match the created feed address");
    }
}
