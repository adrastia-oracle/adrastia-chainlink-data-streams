// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IAccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/IAccessControlEnumerable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Test} from "forge-std/Test.sol";
import {FeedConstants} from "../../FeedConstants.sol";
import {DataStreamsFeed} from "../../../feed/DataStreamsFeed.sol";
import {IVerifierProxy} from "../../../vendor/IVerifierProxy.sol";
import {VerifierStub} from "../../VerifierStub.sol";
import {UpdateHookStub} from "../../UpdateHookStub.sol";
import {PreUpdateHookStub} from "../../PreUpdateHookStub.sol";
import {PostUpdateHookStub} from "../../PostUpdateHookStub.sol";
import {FakeErc20} from "../../FakeErc20.sol";
import {IDataStreamsPostUpdateHook} from "../../../feed/hooks/IDataStreamsPostUpdateHook.sol";
import {IDataStreamsPreUpdateHook} from "../../../feed/hooks/IDataStreamsPreUpdateHook.sol";
import {FeedDataFixture} from "../../FeedDataFixture.sol";
import {AggregatorInterface} from "../../../vendor/AggregatorInterface.sol";
import {AggregatorV2V3Interface} from "../../../vendor/AggregatorV2V3Interface.sol";
import {AggregatorInterface} from "../../../vendor/AggregatorV2V3Interface.sol";
import {AggregatorV3Interface} from "../../../vendor/AggregatorV2V3Interface.sol";
import {IDataStreamsFeed} from "../../../feed/IDataStreamsFeed.sol";
import {AdrastiaDataStreamsCommon} from "../../../common/AdrastiaDataStreamsCommon.sol";
import {FeeManagerStub} from "../../FeeManagerStub.sol";
import {RewardManagerStub} from "../../RewardManagerStub.sol";
import {console2} from "forge-std/console2.sol";

contract DataStreamsFeedTest is Test, FeedConstants, FeedDataFixture {
    IVerifierProxy internal verifierStub;

    DataStreamsFeed.Hook internal NO_HOOK =
        DataStreamsFeed.Hook({hookAddress: address(0), hookGasLimit: 0, allowHookFailure: false});

    function setUp() public {
        vm.warp(1752791789);

        verifierStub = new VerifierStub();
    }

    function test_ConstructorRevertsWhenVerifierProxyIsZeroAddress() public {
        // This test checks that the constructor of DataStreamsFeed reverts
        // when the verifier proxy address is zero.
        // Replace with actual contract deployment and assertion logic.
        // Example:
        vm.expectRevert(DataStreamsFeed.InvalidConstructorArguments.selector);

        new DataStreamsFeed(address(0), FeedConstants.ETH_USD_V3.feedId, ETH_USD_V3.decimals, ETH_USD_V3.description);
    }

    function test_ConstructorRevertsWhenFeedIdIsZero() public {
        // This test checks that the constructor of DataStreamsFeed reverts
        // when the feed ID is zero.
        vm.expectRevert(DataStreamsFeed.InvalidConstructorArguments.selector);

        new DataStreamsFeed(address(verifierStub), bytes32(0), ETH_USD_V3.decimals, ETH_USD_V3.description);
    }

    function test_ConstructorPropsEthUsdV3() public {
        // This test checks that the constructor of DataStreamsFeed initializes correctly
        // with the ETH/USD V3 feed descriptor.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        assertEq(address(feed.verifierProxy()), address(verifierStub));
        assertEq(feed.feedId(), ETH_USD_V3.feedId);
        assertEq(feed.decimals(), ETH_USD_V3.decimals);
        assertEq(feed.description(), ETH_USD_V3.description);
    }

    function test_ConstructorPropsFakeUsd8dV3() public {
        // This test checks that the constructor of DataStreamsFeed initializes correctly
        // with the ETH/USD V3 feed descriptor.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            FAKE_USD_8DEC_V3.feedId,
            FAKE_USD_8DEC_V3.decimals,
            FAKE_USD_8DEC_V3.description
        );

        assertEq(address(feed.verifierProxy()), address(verifierStub));
        assertEq(feed.feedId(), FAKE_USD_8DEC_V3.feedId);
        assertEq(feed.decimals(), FAKE_USD_8DEC_V3.decimals);
        assertEq(feed.description(), FAKE_USD_8DEC_V3.description);
    }

    function test_ConstructorSetsAppropriateRoles() public {
        // This test checks that the constructor of DataStreamsFeed sets the appropriate roles.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        // Deployer should have ADMIN role
        assertTrue(feed.hasRole(feed.ADMIN(), address(this)), "Deployer should have ADMIN role");
        // Nobody should have the REPORT_VERIFIER or UPDATE_PAUSE_ADMIN roles initially
        assertEq(feed.getRoleMemberCount(feed.REPORT_VERIFIER()), 0, "No REPORT_VERIFIER should be set initially");
        assertEq(
            feed.getRoleMemberCount(feed.UPDATE_PAUSE_ADMIN()),
            0,
            "No UPDATE_PAUSE_ADMIN should be set initially"
        );

        // ADMIN should be the admin of ADMIN, REPORT_VERIFIER, and UPDATE_PAUSE_ADMIN roles
        assertEq(feed.getRoleAdmin(feed.ADMIN()), feed.ADMIN(), "ADMIN should be admin of ADMIN");
        assertEq(feed.getRoleAdmin(feed.REPORT_VERIFIER()), feed.ADMIN(), "ADMIN should be admin of REPORT_VERIFIER");
        assertEq(
            feed.getRoleAdmin(feed.UPDATE_PAUSE_ADMIN()),
            feed.ADMIN(),
            "ADMIN should be admin of UPDATE_PAUSE_ADMIN"
        );
    }

    function test_AdminCanGrantVerifierRole() public {
        // This test checks that the ADMIN can grant the REPORT_VERIFIER role.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        address verifier = address(0x123);
        feed.grantRole(feed.REPORT_VERIFIER(), verifier);

        assertTrue(feed.hasRole(feed.REPORT_VERIFIER(), verifier), "Verifier should have REPORT_VERIFIER role");
    }

    function test_AdminCanGrantPauseAdminRole() public {
        // This test checks that the ADMIN can grant the UPDATE_PAUSE_ADMIN role.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        address pauseAdmin = address(0x789);
        feed.grantRole(feed.UPDATE_PAUSE_ADMIN(), pauseAdmin);

        assertTrue(
            feed.hasRole(feed.UPDATE_PAUSE_ADMIN(), pauseAdmin),
            "Pause admin should have UPDATE_PAUSE_ADMIN role"
        );
    }

    function test_RevertsWhenUnauthorizedGrantReportVerifierRole() public {
        // This test checks that only the ADMIN can grant the REPORT_VERIFIER role.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        address unauthorizedUser = address(0x456);
        vm.startPrank(unauthorizedUser);

        address verifier = address(0x123);
        bytes32 role = feed.REPORT_VERIFIER();
        bytes32 adminRole = feed.getRoleAdmin(role);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                adminRole
            )
        );
        feed.grantRole(role, verifier);
    }

    function test_RevertsWhenUnauthorizedGrantPauseAdminRole() public {
        // This test checks that only the ADMIN can grant the UPDATE_PAUSE_ADMIN role.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        address unauthorizedUser = address(0x456);
        vm.startPrank(unauthorizedUser);

        address pauseAdmin = address(0x789);
        bytes32 role = feed.UPDATE_PAUSE_ADMIN();
        bytes32 adminRole = feed.getRoleAdmin(role);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                adminRole
            )
        );
        feed.grantRole(role, pauseAdmin);
    }

    function test_RevertsWhenUnauthorizedPause() public {
        // This test checks that only the UPDATE_PAUSE_ADMIN can pause the feed.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        bytes32 role = feed.UPDATE_PAUSE_ADMIN();

        address unauthorizedUser = address(0x456);
        vm.startPrank(unauthorizedUser);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unauthorizedUser, role)
        );
        feed.setPaused(true);
    }

    function test_RevertsWhenUnpausingButAlreadyUnpaused() public {
        // This test checks that unpausing when the feed is already unpaused reverts.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        feed.grantRole(feed.UPDATE_PAUSE_ADMIN(), address(this));

        vm.expectRevert(DataStreamsFeed.PauseStatusNotChanged.selector);
        feed.setPaused(false);
    }

    function test_RevertsWhenPausingButAlreadyPaused() public {
        // This test checks that pausing when the feed is already paused reverts.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        feed.grantRole(feed.UPDATE_PAUSE_ADMIN(), address(this));

        feed.setPaused(true);
        vm.expectRevert(DataStreamsFeed.PauseStatusNotChanged.selector);
        feed.setPaused(true);
    }

    function test_PauseAdminCanPause() public {
        // This test checks that the UPDATE_PAUSE_ADMIN can pause the feed.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        address pauseAdmin = address(0x789);
        feed.grantRole(feed.UPDATE_PAUSE_ADMIN(), pauseAdmin);

        vm.startPrank(pauseAdmin);
        feed.setPaused(true);

        assertTrue(feed.paused(), "Feed should be paused after calling setPaused(true)");
    }

    function test_PauseAdminCanUnpause() public {
        // This test checks that the UPDATE_PAUSE_ADMIN can unpause the feed.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        address pauseAdmin = address(0x789);
        feed.grantRole(feed.UPDATE_PAUSE_ADMIN(), pauseAdmin);

        vm.startPrank(pauseAdmin);
        feed.setPaused(true);
        assertTrue(feed.paused(), "Feed should be paused after calling setPaused(true)");

        feed.setPaused(false);
        assertFalse(feed.paused(), "Feed should not be paused after calling setPaused(false)");
    }

    function test_HasVersion() public {
        // This test checks that the DataStreamsFeed contract has a version function
        // that returns a non-empty string.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        feed.version();
    }

    function test_NotInitiallyPaused() public {
        // This test checks that the constructor of DataStreamsFeed initializes the feed in a non-paused state.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        assertFalse(feed.paused(), "Feed should not be paused upon initialization");
    }

    function test_NoInitialHooks() public {
        // This test checks that the constructor of DataStreamsFeed does not set any initial hooks.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        DataStreamsFeed.Hook memory preUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate));

        assertEq(preUpdateHook.hookAddress, address(0), "No PreUpdate hook should be set initially");
        assertEq(preUpdateHook.hookGasLimit, 0, "PreUpdate hook gas limit should be zero");
        assertEq(preUpdateHook.allowHookFailure, false, "PreUpdate hook failure should not be allowed");

        DataStreamsFeed.Hook memory postUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate));
        assertEq(postUpdateHook.hookAddress, address(0), "No PostUpdate hook should be set initially");
        assertEq(postUpdateHook.hookGasLimit, 0, "PostUpdate hook gas limit should be zero");
        assertEq(postUpdateHook.allowHookFailure, false, "PostUpdate hook failure should not be allowed");
    }

    function test_NoInitialReport() public {
        // This test checks that the constructor of DataStreamsFeed does not set an initial report.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        vm.expectRevert(DataStreamsFeed.MissingReport.selector);
        feed.latestAnswer();

        vm.expectRevert(DataStreamsFeed.MissingReport.selector);
        feed.latestTimestamp();

        vm.expectRevert(DataStreamsFeed.MissingReport.selector);
        feed.latestRound();

        vm.expectRevert(DataStreamsFeed.MissingReport.selector);
        feed.latestRoundData();

        vm.expectRevert(DataStreamsFeed.MissingReport.selector);
        feed.getAnswer(ROUND_ID_FIRST);

        vm.expectRevert(DataStreamsFeed.MissingReport.selector);
        feed.getTimestamp(ROUND_ID_FIRST);

        vm.expectRevert(DataStreamsFeed.MissingReport.selector);
        feed.getRoundData(ROUND_ID_FIRST);
    }

    function test_RevertsWhenUnauthorizedHookSet() public {
        // This test checks that only the ADMIN can set hooks.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        UpdateHookStub hook = new UpdateHookStub();

        bytes32 adminRole = feed.ADMIN();

        address unauthorizedUser = address(0x456);
        vm.startPrank(unauthorizedUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                adminRole
            )
        );
        feed.setHookConfig(
            uint8(DataStreamsFeed.HookType.PreUpdate),
            DataStreamsFeed.Hook({hookAddress: address(hook), hookGasLimit: 100000, allowHookFailure: false})
        );
    }

    function test_RevertsWhenSettingHookForInvalidHookType() public {
        // This test checks that setting a hook for an invalid hook type reverts.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        UpdateHookStub hook = new UpdateHookStub();

        uint8 invalidHookType = 255; // Invalid hook type

        vm.expectRevert(abi.encodeWithSelector(DataStreamsFeed.InvalidHookType.selector, invalidHookType));
        feed.setHookConfig(
            invalidHookType,
            DataStreamsFeed.Hook({hookAddress: address(hook), hookGasLimit: 100000, allowHookFailure: false})
        );
    }

    function test_RevertsWhenHookConfigDoesntChangeWithNohook() public {
        // This test checks that setting a hook config to no hook reverts if the config doesn't change.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        DataStreamsFeed.Hook memory noHook = DataStreamsFeed.Hook({
            hookAddress: address(0),
            hookGasLimit: 0,
            allowHookFailure: false
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                DataStreamsFeed.HookConfigUnchanged.selector,
                uint8(DataStreamsFeed.HookType.PreUpdate)
            )
        );
        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), noHook);
    }

    function test_RevertsWhenHookConfigDoesntChange() public {
        // This test checks that setting a hook config to the same value reverts.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        UpdateHookStub hook = new UpdateHookStub();

        DataStreamsFeed.Hook memory existingHook = DataStreamsFeed.Hook({
            hookAddress: address(hook),
            hookGasLimit: 100000,
            allowHookFailure: false
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), existingHook);

        vm.expectRevert(
            abi.encodeWithSelector(
                DataStreamsFeed.HookConfigUnchanged.selector,
                uint8(DataStreamsFeed.HookType.PreUpdate)
            )
        );
        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), existingHook);
    }

    function test_RevertsWhenHookConfigHasZeroGasLimit() public {
        // This test checks that setting a hook config with zero gas limit reverts.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        UpdateHookStub hook = new UpdateHookStub();

        vm.expectRevert(
            abi.encodeWithSelector(
                DataStreamsFeed.InvalidHookConfig.selector,
                uint8(DataStreamsFeed.HookType.PreUpdate)
            )
        );
        feed.setHookConfig(
            uint8(DataStreamsFeed.HookType.PreUpdate),
            DataStreamsFeed.Hook({hookAddress: address(hook), hookGasLimit: 0, allowHookFailure: false})
        );
    }

    function test_RevertsWhenRemovingAHookButGasLimitIsNotZero() public {
        // This test checks that removing a hook requires the gas limit to be zero.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        UpdateHookStub hook = new UpdateHookStub();

        feed.setHookConfig(
            uint8(DataStreamsFeed.HookType.PreUpdate),
            DataStreamsFeed.Hook({hookAddress: address(hook), hookGasLimit: 100000, allowHookFailure: false})
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                DataStreamsFeed.InvalidHookConfig.selector,
                uint8(DataStreamsFeed.HookType.PreUpdate)
            )
        );
        feed.setHookConfig(
            uint8(DataStreamsFeed.HookType.PreUpdate),
            DataStreamsFeed.Hook({hookAddress: address(0), hookGasLimit: 100000, allowHookFailure: false})
        );
    }

    function test_RevertsWhenRemovingAHookButAllowHookFailureIsTrue() public {
        // This test checks that removing a hook requires allowHookFailure to be false.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        UpdateHookStub hook = new UpdateHookStub();

        feed.setHookConfig(
            uint8(DataStreamsFeed.HookType.PreUpdate),
            DataStreamsFeed.Hook({hookAddress: address(hook), hookGasLimit: 100000, allowHookFailure: false})
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                DataStreamsFeed.InvalidHookConfig.selector,
                uint8(DataStreamsFeed.HookType.PreUpdate)
            )
        );
        feed.setHookConfig(
            uint8(DataStreamsFeed.HookType.PreUpdate),
            DataStreamsFeed.Hook({hookAddress: address(0), hookGasLimit: 0, allowHookFailure: true})
        );
    }

    function test_RevertsWhenRemovingAHookButBothGasLimitAndAllowHookFailureAreNonZero() public {
        // This test checks that removing a hook requires both gas limit and allowHookFailure to be zero.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        UpdateHookStub hook = new UpdateHookStub();

        feed.setHookConfig(
            uint8(DataStreamsFeed.HookType.PreUpdate),
            DataStreamsFeed.Hook({hookAddress: address(hook), hookGasLimit: 100000, allowHookFailure: false})
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                DataStreamsFeed.InvalidHookConfig.selector,
                uint8(DataStreamsFeed.HookType.PreUpdate)
            )
        );
        feed.setHookConfig(
            uint8(DataStreamsFeed.HookType.PreUpdate),
            DataStreamsFeed.Hook({hookAddress: address(0), hookGasLimit: 100000, allowHookFailure: true})
        );
    }

    function test_RevertsWhenSettingAHookWithTheWrongHookType() public {
        // This test checks that setting a hook with the wrong hook type reverts.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PostUpdateHookStub hook = new PostUpdateHookStub();

        vm.expectRevert(
            abi.encodeWithSelector(
                DataStreamsFeed.HookDoesntSupportInterface.selector,
                uint8(DataStreamsFeed.HookType.PreUpdate),
                address(hook),
                type(IDataStreamsPreUpdateHook).interfaceId
            )
        );
        feed.setHookConfig(
            uint8(DataStreamsFeed.HookType.PreUpdate),
            DataStreamsFeed.Hook({hookAddress: address(hook), hookGasLimit: 100000, allowHookFailure: false})
        );
    }

    function test_RevertsWhenSettingAHookWithABadAddress() public {
        // This test checks that setting a hook with a bad address reverts.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        address badAddress = address(0x123); // Not a valid hook contract

        vm.expectRevert(
            abi.encodeWithSelector(
                DataStreamsFeed.HookDoesntSupportInterface.selector,
                uint8(DataStreamsFeed.HookType.PreUpdate),
                badAddress,
                type(IDataStreamsPreUpdateHook).interfaceId
            )
        );
        feed.setHookConfig(
            uint8(DataStreamsFeed.HookType.PreUpdate),
            DataStreamsFeed.Hook({hookAddress: badAddress, hookGasLimit: 100000, allowHookFailure: false})
        );
    }

    function test_SetsAPreUpdateHook() public {
        // This test checks that setting a PreUpdate hook works correctly.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub hook = new PreUpdateHookStub();

        DataStreamsFeed.Hook memory hookConfig = DataStreamsFeed.Hook({
            hookAddress: address(hook),
            hookGasLimit: 100000,
            allowHookFailure: false
        });

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookConfigUpdated(
            address(this),
            uint8(DataStreamsFeed.HookType.PreUpdate),
            NO_HOOK,
            hookConfig,
            block.timestamp
        );

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), hookConfig);

        DataStreamsFeed.Hook memory preUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate));

        assertEq(preUpdateHook.hookAddress, hookConfig.hookAddress, "PreUpdate hook address should match");
        assertEq(preUpdateHook.hookGasLimit, hookConfig.hookGasLimit, "PreUpdate hook gas limit should match");
        assertEq(preUpdateHook.allowHookFailure, hookConfig.allowHookFailure, "PreUpdate hook failure should match");

        DataStreamsFeed.Hook memory postUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate));
        assertEq(postUpdateHook.hookAddress, NO_HOOK.hookAddress, "PostUpdate hook address should be zero");
        assertEq(postUpdateHook.hookGasLimit, NO_HOOK.hookGasLimit, "PostUpdate hook gas limit should be zero");
        assertEq(
            postUpdateHook.allowHookFailure,
            NO_HOOK.allowHookFailure,
            "PostUpdate hook failure should not be allowed"
        );
    }

    function test_SetsAPostUpdateHook() public {
        // This test checks that setting a PostUpdate hook works correctly.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PostUpdateHookStub hook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory hookConfig = DataStreamsFeed.Hook({
            hookAddress: address(hook),
            hookGasLimit: 100000,
            allowHookFailure: false
        });

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookConfigUpdated(
            address(this),
            uint8(DataStreamsFeed.HookType.PostUpdate),
            NO_HOOK,
            hookConfig,
            block.timestamp
        );

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), hookConfig);

        DataStreamsFeed.Hook memory preUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate));
        assertEq(preUpdateHook.hookAddress, NO_HOOK.hookAddress, "PreUpdate hook address should be zero");
        assertEq(preUpdateHook.hookGasLimit, NO_HOOK.hookGasLimit, "PreUpdate hook gas limit should be zero");
        assertEq(
            preUpdateHook.allowHookFailure,
            NO_HOOK.allowHookFailure,
            "PreUpdate hook failure should not be allowed"
        );

        DataStreamsFeed.Hook memory postUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate));
        assertEq(postUpdateHook.hookAddress, hookConfig.hookAddress, "PostUpdate hook address should match");
        assertEq(postUpdateHook.hookGasLimit, hookConfig.hookGasLimit, "PostUpdate hook gas limit should match");
        assertEq(postUpdateHook.allowHookFailure, hookConfig.allowHookFailure, "PostUpdate hook failure should match");
    }

    function test_SetsPreAndPostUpdateHooks() public {
        // This test checks that setting both PreUpdate and PostUpdate hooks works correctly.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();
        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 100000,
            allowHookFailure: false
        });

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 9998,
            allowHookFailure: true
        });

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookConfigUpdated(
            address(this),
            uint8(DataStreamsFeed.HookType.PreUpdate),
            NO_HOOK,
            preHookConfig,
            block.timestamp
        );
        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookConfigUpdated(
            address(this),
            uint8(DataStreamsFeed.HookType.PostUpdate),
            NO_HOOK,
            postHookConfig,
            block.timestamp
        );
        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        DataStreamsFeed.Hook memory preUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate));
        assertEq(preUpdateHook.hookAddress, preHookConfig.hookAddress, "PreUpdate hook address should match");
        assertEq(preUpdateHook.hookGasLimit, preHookConfig.hookGasLimit, "PreUpdate hook gas limit should match");
        assertEq(preUpdateHook.allowHookFailure, preHookConfig.allowHookFailure, "PreUpdate hook failure should match");

        DataStreamsFeed.Hook memory postUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate));
        assertEq(postUpdateHook.hookAddress, postHookConfig.hookAddress, "PostUpdate hook address should match");
        assertEq(postUpdateHook.hookGasLimit, postHookConfig.hookGasLimit, "PostUpdate hook gas limit should match");
        assertEq(
            postUpdateHook.allowHookFailure,
            postHookConfig.allowHookFailure,
            "PostUpdate hook failure should match"
        );
    }

    function test_RemoveAPreUpdateHook() public {
        // This test checks that removing a PreUpdate hook works correctly.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub hook = new PreUpdateHookStub();

        DataStreamsFeed.Hook memory hookConfig = DataStreamsFeed.Hook({
            hookAddress: address(hook),
            hookGasLimit: 100000,
            allowHookFailure: false
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), hookConfig);

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookConfigUpdated(
            address(this),
            uint8(DataStreamsFeed.HookType.PreUpdate),
            hookConfig,
            NO_HOOK,
            block.timestamp
        );

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), NO_HOOK);

        DataStreamsFeed.Hook memory preUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate));
        assertEq(preUpdateHook.hookAddress, NO_HOOK.hookAddress, "PreUpdate hook address should be zero");
        assertEq(preUpdateHook.hookGasLimit, NO_HOOK.hookGasLimit, "PreUpdate hook gas limit should be zero");
        assertEq(
            preUpdateHook.allowHookFailure,
            NO_HOOK.allowHookFailure,
            "PreUpdate hook failure should not be allowed"
        );

        DataStreamsFeed.Hook memory postUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate));
        assertEq(postUpdateHook.hookAddress, NO_HOOK.hookAddress, "PostUpdate hook address should be zero");
        assertEq(postUpdateHook.hookGasLimit, NO_HOOK.hookGasLimit, "PostUpdate hook gas limit should be zero");
        assertEq(
            postUpdateHook.allowHookFailure,
            NO_HOOK.allowHookFailure,
            "PostUpdate hook failure should not be allowed"
        );
    }

    function test_RemoveAPostUpdateHook() public {
        // This test checks that removing a PostUpdate hook works correctly.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PostUpdateHookStub hook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory hookConfig = DataStreamsFeed.Hook({
            hookAddress: address(hook),
            hookGasLimit: 100000,
            allowHookFailure: false
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), hookConfig);

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookConfigUpdated(
            address(this),
            uint8(DataStreamsFeed.HookType.PostUpdate),
            hookConfig,
            NO_HOOK,
            block.timestamp
        );

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), NO_HOOK);

        DataStreamsFeed.Hook memory preUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate));
        assertEq(preUpdateHook.hookAddress, NO_HOOK.hookAddress, "PreUpdate hook address should be zero");
        assertEq(preUpdateHook.hookGasLimit, NO_HOOK.hookGasLimit, "PreUpdate hook gas limit should be zero");
        assertEq(
            preUpdateHook.allowHookFailure,
            NO_HOOK.allowHookFailure,
            "PreUpdate hook failure should not be allowed"
        );

        DataStreamsFeed.Hook memory postUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate));
        assertEq(postUpdateHook.hookAddress, NO_HOOK.hookAddress, "PostUpdate hook address should be zero");
        assertEq(postUpdateHook.hookGasLimit, NO_HOOK.hookGasLimit, "PostUpdate hook gas limit should be zero");
        assertEq(
            postUpdateHook.allowHookFailure,
            NO_HOOK.allowHookFailure,
            "PostUpdate hook failure should not be allowed"
        );
    }

    function test_RemovingAPostUpdateHookDoesntRemoveThePreUpdateHook() public {
        // This test checks that removing a PostUpdate hook does not affect the PreUpdate hook.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();
        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 100000,
            allowHookFailure: false
        });

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 9998,
            allowHookFailure: true
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);
        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookConfigUpdated(
            address(this),
            uint8(DataStreamsFeed.HookType.PostUpdate),
            postHookConfig,
            NO_HOOK,
            block.timestamp
        );

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), NO_HOOK);

        DataStreamsFeed.Hook memory preUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate));
        assertEq(preUpdateHook.hookAddress, preHookConfig.hookAddress, "PreUpdate hook address should match");
        assertEq(preUpdateHook.hookGasLimit, preHookConfig.hookGasLimit, "PreUpdate hook gas limit should match");
        assertEq(preUpdateHook.allowHookFailure, preHookConfig.allowHookFailure, "PreUpdate hook failure should match");

        DataStreamsFeed.Hook memory postUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate));
        assertEq(postUpdateHook.hookAddress, NO_HOOK.hookAddress, "PostUpdate hook address should be zero");
        assertEq(postUpdateHook.hookGasLimit, NO_HOOK.hookGasLimit, "PostUpdate hook gas limit should be zero");
        assertEq(
            postUpdateHook.allowHookFailure,
            NO_HOOK.allowHookFailure,
            "PostUpdate hook failure should not be allowed"
        );
    }

    function test_RemovingAPreUpdateHookDoesntRemoveThePostUpdateHook() public {
        // This test checks that removing a PreUpdate hook does not affect the PostUpdate hook.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();
        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 100000,
            allowHookFailure: false
        });

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 9998,
            allowHookFailure: true
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);
        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookConfigUpdated(
            address(this),
            uint8(DataStreamsFeed.HookType.PreUpdate),
            preHookConfig,
            NO_HOOK,
            block.timestamp
        );

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), NO_HOOK);

        DataStreamsFeed.Hook memory preUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate));
        assertEq(preUpdateHook.hookAddress, NO_HOOK.hookAddress, "PreUpdate hook address should be zero");
        assertEq(preUpdateHook.hookGasLimit, NO_HOOK.hookGasLimit, "PreUpdate hook gas limit should be zero");
        assertEq(
            preUpdateHook.allowHookFailure,
            NO_HOOK.allowHookFailure,
            "PreUpdate hook failure should not be allowed"
        );

        DataStreamsFeed.Hook memory postUpdateHook = feed.getHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate));
        assertEq(postUpdateHook.hookAddress, postHookConfig.hookAddress, "PostUpdate hook address should match");
        assertEq(postUpdateHook.hookGasLimit, postHookConfig.hookGasLimit, "PostUpdate hook gas limit should match");
        assertEq(
            postUpdateHook.allowHookFailure,
            postHookConfig.allowHookFailure,
            "PostUpdate hook failure should match"
        );
    }

    function test_RevertsWhenUnauthorizedErc20Withdrawal() public {
        // This test checks that only the ADMIN can withdraw ERC20 tokens.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );
        FakeErc20 fakeErc20 = new FakeErc20();

        // Send some tokens to the feed contract
        uint256 amount = 1 * 10 ** fakeErc20.decimals();
        fakeErc20.transfer(address(feed), amount);

        address unauthorizedUser = address(0x456);
        vm.startPrank(unauthorizedUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                feed.ADMIN()
            )
        );
        feed.withdrawErc20(address(fakeErc20), address(unauthorizedUser), amount);
    }

    function test_AdminCanWithdrawErc20() public {
        // This test checks that the ADMIN can withdraw ERC20 tokens.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );
        FakeErc20 fakeErc20 = new FakeErc20();

        // Send some tokens to the feed contract
        uint256 amount = 1 * 10 ** fakeErc20.decimals();
        fakeErc20.transfer(address(feed), amount);

        address recipient = address(0x123);

        // Withdraw the tokens
        feed.withdrawErc20(address(fakeErc20), recipient, amount);

        assertEq(fakeErc20.balanceOf(recipient), amount, "Recipient should have received the withdrawn tokens");
    }

    function test_RevertsWhenWithdrawingMoreThanBalance() public {
        // This test checks that the ADMIN cannot withdraw more tokens than the contract holds.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );
        FakeErc20 fakeErc20 = new FakeErc20();

        // Send some tokens to the feed contract
        uint256 amount = 1 * 10 ** fakeErc20.decimals();
        fakeErc20.transfer(address(feed), amount);

        address recipient = address(0x123);

        // Attempt to withdraw more than the balance
        vm.expectRevert();
        feed.withdrawErc20(address(fakeErc20), recipient, amount + 1);
    }

    function describeBasicVerifyTest(uint8 reportVersion) internal {
        bytes32 feedId = reportVersion == 8 ? USR_USD_V7.feedId : reportVersion == 7
            ? AAPL_USD_V8.feedId
            : reportVersion == 4
            ? ETH_USD_V4.feedId
            : reportVersion == 3
            ? ETH_USD_V3.feedId
            : ETH_USD_V2.feedId;

        // This test checks that a valid report can be verified and stored.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp - 3600); // Valid from 1 hour ago
        uint32 observationsTimestamp = validFrom + 1;
        uint32 expiresAt = uint32(block.timestamp + 3600); // Expires in 1 hour

        // Create a valid report
        bytes memory unverifiedReport = generateReportData(
            feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        // Check that the report was stored correctly
        uint32 expectedRoundId = ROUND_ID_FIRST;

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectEmit(true, true, true, true);

        emit AggregatorInterface.AnswerUpdated(price, observationsTimestamp, block.timestamp);

        vm.expectEmit(true, true, true, true);

        emit DataStreamsFeed.ReportUpdated(
            feedId,
            address(this),
            expectedRoundId,
            price,
            validFrom,
            observationsTimestamp,
            expiresAt,
            uint32(block.timestamp)
        );

        // Verify and store the report
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        assertEq(feed.latestAnswer(), price, "Latest answer should match the report price");
        assertEq(
            feed.latestTimestamp(),
            observationsTimestamp,
            "Latest timestamp should match the report observationsTimestamp"
        );
        assertEq(feed.latestRound(), expectedRoundId, "Latest round should equal 1");

        assertEq(feed.getAnswer(expectedRoundId), price, "Answer for the first round should match the report price");
        assertEq(
            feed.getTimestamp(expectedRoundId),
            observationsTimestamp,
            "Timestamp for the first round should match the report observationsTimestamp"
        );
        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) = feed
            .getRoundData(expectedRoundId);

        assertEq(roundId, expectedRoundId, "Round ID should match the expected round ID");
        assertEq(answer, price, "Answer for the first round should match the report price");
        assertEq(startedAt, observationsTimestamp, "Started at should match the report observationsTimestamp");
        assertEq(updatedAt, block.timestamp, "Updated at should match the current timestamp");
        assertEq(answeredInRound, expectedRoundId, "Answered in round should match the expected round ID");

        // Check latestRoundData
        (roundId, answer, startedAt, updatedAt, answeredInRound) = feed.latestRoundData();

        assertEq(roundId, expectedRoundId, "Latest round ID should match the expected round ID");
        assertEq(answer, price, "Latest answer should match the report price");
        assertEq(startedAt, observationsTimestamp, "Latest started at should match the report observationsTimestamp");
        assertEq(updatedAt, block.timestamp, "Latest updated at should match the current timestamp");
        assertEq(answeredInRound, expectedRoundId, "Latest answered in round should match the expected round ID");
    }

    function test_verifyAndUpdateReport_VerifiesAndStoresValidReportV8() public {
        describeBasicVerifyTest(8);
    }

    function test_verifyAndUpdateReport_VerifiesAndStoresValidReportV7() public {
        describeBasicVerifyTest(7);
    }

    function test_verifyAndUpdateReport_VerifiesAndStoresValidReportV4() public {
        describeBasicVerifyTest(4);
    }

    function test_verifyAndUpdateReport_VerifiesAndStoresValidReportV3() public {
        describeBasicVerifyTest(3);
    }

    function test_verifyAndUpdateReport_VerifiesAndStoresValidReportV2() public {
        describeBasicVerifyTest(2);
    }

    function describeBasicFailingVerifyTest(uint8 reportVersion) internal {
        bytes32 feedId = reportVersion == 8 ? AAPL_USD_V8.feedId : reportVersion == 7
            ? USR_USD_V7.feedId
            : reportVersion == 4
            ? ETH_USD_V4.feedId
            : reportVersion == 3
            ? ETH_USD_V3.feedId
            : ETH_USD_V2.feedId;

        // This test checks that an invalid report cannot be verified and stored.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp - 3600); // Valid from 1 hour ago
        uint32 observationsTimestamp = validFrom + 1;
        uint32 expiresAt = uint32(block.timestamp + 3600); // Expires in 1 hour

        // Create an invalid report (not signed)
        bytes memory unverifiedReport = generateReportData(
            feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            false
        );

        bytes memory parameterPayload = abi.encode(address(0));

        // Attempt to verify
        vm.expectRevert(abi.encodePacked("REPORT_NOT_SIGNED"));
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_RevertsWhenReportV8IsInvalid() public {
        describeBasicFailingVerifyTest(8);
    }

    function test_verifyAndUpdateReport_RevertsWhenReportV7IsInvalid() public {
        describeBasicFailingVerifyTest(7);
    }

    function test_verifyAndUpdateReport_RevertsWhenReportV4IsInvalid() public {
        describeBasicFailingVerifyTest(4);
    }

    function test_verifyAndUpdateReport_RevertsWhenReportV3IsInvalid() public {
        describeBasicFailingVerifyTest(3);
    }

    function test_verifyAndUpdateReport_RevertsWhenReportV2IsInvalid() public {
        describeBasicFailingVerifyTest(2);
    }

    function test_verifyAndUpdateReport_revertsWhenUpdatesPaused() public {
        // This test checks that verifying and updating a report reverts when updates are paused.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        // Pause updates
        feed.grantRole(feed.UPDATE_PAUSE_ADMIN(), address(this));
        feed.setPaused(true);

        // Create a valid report
        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectRevert(abi.encodeWithSelector(DataStreamsFeed.UpdatesPaused.selector));
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_revertsWhenFeedMismatch_V4() public {
        // This test checks that verifying and updating a report reverts when the feed ID does not match.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        // Create a valid report with a different feed ID
        bytes memory unverifiedReport = generateSimpleReportData(BTC_USD_V4.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectRevert(
            abi.encodeWithSelector(DataStreamsFeed.FeedMismatch.selector, ETH_USD_V3.feedId, BTC_USD_V4.feedId)
        );
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_revertsWhenFeedMismatch_V3() public {
        // This test checks that verifying and updating a report reverts when the feed ID does not match.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        // Create a valid report with a different feed ID
        bytes memory unverifiedReport = generateSimpleReportData(BTC_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectRevert(
            abi.encodeWithSelector(DataStreamsFeed.FeedMismatch.selector, ETH_USD_V3.feedId, BTC_USD_V3.feedId)
        );
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_revertsWhenFeedMismatch_V2() public {
        // This test checks that verifying and updating a report reverts when the feed ID does not match.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        // Create a valid report with a different feed ID
        bytes memory unverifiedReport = generateSimpleReportData(BTC_USD_V2.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectRevert(
            abi.encodeWithSelector(DataStreamsFeed.FeedMismatch.selector, ETH_USD_V3.feedId, BTC_USD_V2.feedId)
        );
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_revertsWhenReportVersionIsUnsupported() public {
        // This test checks that verifying and updating a report reverts when the report version is unsupported.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        uint8 version = UNSUPPORTED_REPORT_VERSION;

        // Create a valid report with an unsupported version
        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V60.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectRevert(abi.encodeWithSelector(AdrastiaDataStreamsCommon.InvalidReportVersion.selector, version));
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function describe_verifyAndUpdateReport_expiredReportTest(uint8 reportVersion, uint32 secondsExpired) internal {
        bytes32 feedId = reportVersion == 8 ? AAPL_USD_V8.feedId : reportVersion == 7
            ? USR_USD_V7.feedId
            : reportVersion == 4
            ? ETH_USD_V4.feedId
            : reportVersion == 3
            ? ETH_USD_V3.feedId
            : ETH_USD_V2.feedId;

        // This test checks that an expired report cannot be verified and stored.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp - 7200); // Valid from 2 hours ago
        uint32 observationsTimestamp = validFrom + 1;
        uint32 expiresAt = uint32(block.timestamp - secondsExpired);

        bytes memory unverifiedReport = generateReportData(
            feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectRevert(abi.encodeWithSelector(DataStreamsFeed.ReportIsExpired.selector, expiresAt, block.timestamp));
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsExpired_V8_0secondsAgo() public {
        describe_verifyAndUpdateReport_expiredReportTest(8, 0);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsExpired_V8_1secondAgo() public {
        describe_verifyAndUpdateReport_expiredReportTest(8, 1);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsExpired_V7_0secondsAgo() public {
        describe_verifyAndUpdateReport_expiredReportTest(7, 0);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsExpired_V7_1secondAgo() public {
        describe_verifyAndUpdateReport_expiredReportTest(7, 1);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsExpired_V4_0secondsAgo() public {
        describe_verifyAndUpdateReport_expiredReportTest(4, 0);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsExpired_V4_1secondAgo() public {
        describe_verifyAndUpdateReport_expiredReportTest(4, 1);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsExpired_V3_0secondsAgo() public {
        describe_verifyAndUpdateReport_expiredReportTest(3, 0);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsExpired_V3_1secondAgo() public {
        describe_verifyAndUpdateReport_expiredReportTest(3, 1);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsExpired_V2_0secondsAgo() public {
        describe_verifyAndUpdateReport_expiredReportTest(2, 0);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsExpired_V2_1secondAgo() public {
        describe_verifyAndUpdateReport_expiredReportTest(2, 1);
    }

    function describe_verifyAndUpdateReport_notValidYetTest(uint8 reportVersion) internal {
        bytes32 feedId = reportVersion == 8 ? AAPL_USD_V8.feedId : reportVersion == 7
            ? USR_USD_V7.feedId
            : reportVersion == 4
            ? ETH_USD_V4.feedId
            : reportVersion == 3
            ? ETH_USD_V3.feedId
            : ETH_USD_V2.feedId;

        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp + 1); // Valid in 1 second
        uint32 observationsTimestamp = validFrom;
        uint32 expiresAt = uint32(block.timestamp + 7200); // Expires in 2 hours

        bytes memory unverifiedReport = generateReportData(
            feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectRevert(
            abi.encodeWithSelector(DataStreamsFeed.ReportIsNotValidYet.selector, validFrom, block.timestamp)
        );
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsNotValidYet_V8() public {
        describe_verifyAndUpdateReport_notValidYetTest(8);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsNotValidYet_V7() public {
        describe_verifyAndUpdateReport_notValidYetTest(7);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsNotValidYet_V4() public {
        describe_verifyAndUpdateReport_notValidYetTest(4);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsNotValidYet_V3() public {
        describe_verifyAndUpdateReport_notValidYetTest(3);
    }

    function test_verifyAndUpdateReport_revertsWhenReportIsNotValidYet_V2() public {
        describe_verifyAndUpdateReport_notValidYetTest(2);
    }

    function describe_verifyAndUpdateReport_observationsTimestampInFuture(uint8 reportVersion) internal {
        bytes32 feedId = reportVersion == 8 ? AAPL_USD_V8.feedId : reportVersion == 7
            ? USR_USD_V7.feedId
            : reportVersion == 4
            ? ETH_USD_V4.feedId
            : reportVersion == 3
            ? ETH_USD_V3.feedId
            : ETH_USD_V2.feedId;

        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp - 1); // Valid as of 1 second ago
        uint32 observationsTimestamp = uint32(block.timestamp + 1); // Observations timestamp in the future
        uint32 expiresAt = uint32(block.timestamp + 7200); // Expires in 2 hours

        bytes memory unverifiedReport = generateReportData(
            feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectRevert(
            abi.encodeWithSelector(
                DataStreamsFeed.ReportObservationTimeInFuture.selector,
                observationsTimestamp,
                block.timestamp
            )
        );
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_revertsWhenObservationsTimestampInFuture_V8() public {
        describe_verifyAndUpdateReport_observationsTimestampInFuture(8);
    }

    function test_verifyAndUpdateReport_revertsWhenObservationsTimestampInFuture_V7() public {
        describe_verifyAndUpdateReport_observationsTimestampInFuture(7);
    }

    function test_verifyAndUpdateReport_revertsWhenObservationsTimestampInFuture_V4() public {
        describe_verifyAndUpdateReport_observationsTimestampInFuture(4);
    }

    function test_verifyAndUpdateReport_revertsWhenObservationsTimestampInFuture_V3() public {
        describe_verifyAndUpdateReport_observationsTimestampInFuture(3);
    }

    function test_verifyAndUpdateReport_revertsWhenObservationsTimestampInFuture_V2() public {
        describe_verifyAndUpdateReport_observationsTimestampInFuture(2);
    }

    function describe_verifyAndUpdateReport_duplicateReport(uint8 reportVersion) internal {
        bytes32 feedId = reportVersion == 8 ? AAPL_USD_V8.feedId : reportVersion == 7
            ? USR_USD_V7.feedId
            : reportVersion == 4
            ? ETH_USD_V4.feedId
            : reportVersion == 3
            ? ETH_USD_V3.feedId
            : ETH_USD_V2.feedId;

        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        bytes memory unverifiedReport = generateSimpleReportData(feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        // First verification should succeed
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        vm.expectRevert(abi.encodeWithSelector(DataStreamsFeed.DuplicateReport.selector));
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_revertsWhenDuplicateReport_V8() public {
        describe_verifyAndUpdateReport_duplicateReport(8);
    }

    function test_verifyAndUpdateReport_revertsWhenDuplicateReport_V7() public {
        describe_verifyAndUpdateReport_duplicateReport(7);
    }

    function test_verifyAndUpdateReport_revertsWhenDuplicateReport_V4() public {
        describe_verifyAndUpdateReport_duplicateReport(4);
    }

    function test_verifyAndUpdateReport_revertsWhenDuplicateReport_V3() public {
        describe_verifyAndUpdateReport_duplicateReport(3);
    }

    function test_verifyAndUpdateReport_revertsWhenDuplicateReport_V2() public {
        describe_verifyAndUpdateReport_duplicateReport(2);
    }

    function describe_verifyAndUpdateReport_staleReport(uint8 reportVersion, uint32 secondsStale) internal {
        bytes32 feedId = reportVersion == 8 ? AAPL_USD_V8.feedId : reportVersion == 7
            ? USR_USD_V7.feedId
            : reportVersion == 4
            ? ETH_USD_V4.feedId
            : reportVersion == 3
            ? ETH_USD_V3.feedId
            : ETH_USD_V2.feedId;

        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp - 7200); // Valid as of 2 hours ago
        uint32 observationsTimestamp = uint32(block.timestamp - 1); // Observations timestamp 1 second ago
        uint32 expiresAt = uint32(block.timestamp + 7200); // Expires in 2 hours

        bytes memory unverifiedReport = generateReportData(
            feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));

        // First verification should succeed
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        unverifiedReport = generateReportData(
            feedId,
            validFrom,
            observationsTimestamp - secondsStale,
            expiresAt,
            price + 1, // Slightly different price to simulate a new report
            true
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                DataStreamsFeed.StaleReport.selector,
                observationsTimestamp,
                observationsTimestamp - secondsStale
            )
        );
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_revertsWhenStaleReport_V8_0scondsStale() public {
        describe_verifyAndUpdateReport_staleReport(8, 0);
    }

    function test_verifyAndUpdateReport_revertsWhenStaleReport_V8_1secondStale() public {
        describe_verifyAndUpdateReport_staleReport(8, 1);
    }

    function test_verifyAndUpdateReport_revertsWhenStaleReport_V7_0scondsStale() public {
        describe_verifyAndUpdateReport_staleReport(7, 0);
    }

    function test_verifyAndUpdateReport_revertsWhenStaleReport_V7_1secondStale() public {
        describe_verifyAndUpdateReport_staleReport(7, 1);
    }

    function test_verifyAndUpdateReport_revertsWhenStaleReport_V4_0scondsStale() public {
        describe_verifyAndUpdateReport_staleReport(4, 0);
    }

    function test_verifyAndUpdateReport_revertsWhenStaleReport_V4_1secondStale() public {
        describe_verifyAndUpdateReport_staleReport(4, 1);
    }

    function test_verifyAndUpdateReport_revertsWhenStaleReport_V3_0scondsStale() public {
        describe_verifyAndUpdateReport_staleReport(3, 0);
    }

    function test_verifyAndUpdateReport_revertsWhenStaleReport_V3_1secondStale() public {
        describe_verifyAndUpdateReport_staleReport(3, 1);
    }

    function test_verifyAndUpdateReport_revertsWhenStaleReport_V2_0scondsStale() public {
        describe_verifyAndUpdateReport_staleReport(2, 0);
    }

    function test_verifyAndUpdateReport_revertsWhenStaleReport_V2_1secondStale() public {
        describe_verifyAndUpdateReport_staleReport(2, 1);
    }

    function describe_verifyAndUpdateReport_observationsTimestampIsZero(uint8 reportVersion) internal {
        bytes32 feedId = reportVersion == 8 ? AAPL_USD_V8.feedId : reportVersion == 7
            ? USR_USD_V7.feedId
            : reportVersion == 4
            ? ETH_USD_V4.feedId
            : reportVersion == 3
            ? ETH_USD_V3.feedId
            : ETH_USD_V2.feedId;

        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(0);
        uint32 observationsTimestamp = uint32(0);
        uint32 expiresAt = uint32(block.timestamp + 7200); // Expires in 2 hours

        bytes memory unverifiedReport = generateReportData(
            feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectRevert(abi.encodeWithSelector(DataStreamsFeed.InvalidReport.selector));
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_revertsWhenObservationsTimestampIsZero_V8() public {
        describe_verifyAndUpdateReport_observationsTimestampIsZero(8);
    }

    function test_verifyAndUpdateReport_revertsWhenObservationsTimestampIsZero_V7() public {
        describe_verifyAndUpdateReport_observationsTimestampIsZero(7);
    }

    function test_verifyAndUpdateReport_revertsWhenObservationsTimestampIsZero_V4() public {
        describe_verifyAndUpdateReport_observationsTimestampIsZero(4);
    }

    function test_verifyAndUpdateReport_revertsWhenObservationsTimestampIsZero_V3() public {
        describe_verifyAndUpdateReport_observationsTimestampIsZero(3);
    }

    function test_verifyAndUpdateReport_revertsWhenObservationsTimestampIsZero_V2() public {
        describe_verifyAndUpdateReport_observationsTimestampIsZero(2);
    }

    function test_verifyAndUpdateReport_callsPreUpdateHook() public {
        // This test checks that the PreUpdate hook is called before updating the report.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 1_000_000,
            allowHookFailure: false
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp - 3600); // Valid from 1 hour ago
        uint32 observationsTimestamp = uint32(block.timestamp - 1);
        uint32 expiresAt = uint32(block.timestamp + 7200); // Expires in 2 hours

        bytes memory unverifiedReport = generateReportData(
            ETH_USD_V3.feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        assertEq(preHook.preUpdateHookCallTimes(), 1, "PreUpdate hook should have been called once");

        assertEq(preHook.preLastFeedId(), ETH_USD_V3.feedId, "PreUpdate hook should have the correct feed ID");
        assertEq(preHook.preLastRoundId(), ROUND_ID_FIRST, "PreUpdate hook should have the correct round ID");
        assertEq(preHook.preLastPrice(), price, "PreUpdate hook should have the correct answer");
        assertEq(
            preHook.preLastObservationTimestamp(),
            observationsTimestamp,
            "PreUpdate hook should have the correct observationsTimestamp"
        );
        assertEq(preHook.preLastExpiresAt(), expiresAt, "PreUpdate hook should have the correct expiresAt timestamp");
        assertEq(
            preHook.preLastUpdatedAt(),
            uint32(block.timestamp),
            "PreUpdate hook should have the correct updatedAt timestamp"
        );
    }

    function test_verifyAndUpdateReport_callsPostUpdateHook() public {
        // This test checks that the PostUpdate hook is called after updating the report.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 1_000_000,
            allowHookFailure: false
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp - 3600); // Valid from 1 hour ago
        uint32 observationsTimestamp = uint32(block.timestamp - 1);
        uint32 expiresAt = uint32(block.timestamp + 7200); // Expires in 2 hours

        bytes memory unverifiedReport = generateReportData(
            ETH_USD_V3.feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        assertEq(postHook.postUpdateHookCallTimes(), 1, "PostUpdate hook should have been called once");

        assertEq(postHook.postLastFeedId(), ETH_USD_V3.feedId, "PostUpdate hook should have the correct feed ID");
        assertEq(postHook.postLastRoundId(), ROUND_ID_FIRST, "PostUpdate hook should have the correct round ID");
        assertEq(postHook.postLastPrice(), price, "PostUpdate hook should have the correct answer");
        assertEq(
            postHook.postLastObservationTimestamp(),
            observationsTimestamp,
            "PostUpdate hook should have the correct observationsTimestamp"
        );
        assertEq(
            postHook.postLastExpiresAt(),
            expiresAt,
            "PostUpdate hook should have the correct expiresAt timestamp"
        );
        assertEq(
            postHook.postLastUpdatedAt(),
            uint32(block.timestamp),
            "PostUpdate hook should have the correct updatedAt timestamp"
        );
    }

    function test_verifyAndUpdateReport_callsPreAndPostUpdateHooks() public {
        // This test checks that both PreUpdate and PostUpdate hooks are called during report verification.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();
        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 1_000_000,
            allowHookFailure: false
        });

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 1_000_000,
            allowHookFailure: false
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);
        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp - 3600); // Valid from 1 hour ago
        uint32 observationsTimestamp = uint32(block.timestamp - 1);
        uint32 expiresAt = uint32(block.timestamp + 7200); // Expires in 2 hours

        bytes memory unverifiedReport = generateReportData(
            ETH_USD_V3.feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        assertEq(preHook.preUpdateHookCallTimes(), 1, "PreUpdate hook should have been called once");
        assertEq(postHook.postUpdateHookCallTimes(), 1, "PostUpdate hook should have been called once");

        assertEq(preHook.preLastFeedId(), ETH_USD_V3.feedId, "PreUpdate hook should have the correct feed ID");
        assertEq(preHook.preLastRoundId(), ROUND_ID_FIRST, "PreUpdate hook should have the correct round ID");
        assertEq(preHook.preLastPrice(), price, "PreUpdate hook should have the correct answer");
        assertEq(
            preHook.preLastObservationTimestamp(),
            observationsTimestamp,
            "PreUpdate hook should have the correct observationsTimestamp"
        );
        assertEq(preHook.preLastExpiresAt(), expiresAt, "PreUpdate hook should have the correct expiresAt timestamp");
        assertEq(
            preHook.preLastUpdatedAt(),
            uint32(block.timestamp),
            "PreUpdate hook should have the correct updatedAt timestamp"
        );

        assertEq(postHook.postLastFeedId(), ETH_USD_V3.feedId, "PostUpdate hook should have the correct feed ID");
        assertEq(postHook.postLastRoundId(), ROUND_ID_FIRST, "PostUpdate hook should have the correct round ID");
        assertEq(postHook.postLastPrice(), price, "PostUpdate hook should have the correct answer");
        assertEq(
            postHook.postLastObservationTimestamp(),
            observationsTimestamp,
            "PostUpdate hook should have the correct observationsTimestamp"
        );
        assertEq(
            postHook.postLastExpiresAt(),
            expiresAt,
            "PostUpdate hook should have the correct expiresAt timestamp"
        );
        assertEq(
            postHook.postLastUpdatedAt(),
            uint32(block.timestamp),
            "PostUpdate hook should have the correct updatedAt timestamp"
        );
    }

    function test_verifyAndUpdateReport_allowPreUpdateHookFailure_reverts() public {
        // This test checks that if allowHookFailure is true, the PreUpdate hook failure does not revert.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 1_000_000,
            allowHookFailure: true
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        string memory expectedError = "PreUpdate hook failed";
        bytes memory expectedRevertData = abi.encodeWithSignature("Error(string)", expectedError);

        preHook.stubSetPreUpdateHookReverts(true, expectedError);

        vm.expectEmit(true, true, true, true);

        emit DataStreamsFeed.HookFailed(
            uint256(DataStreamsFeed.HookType.PreUpdate),
            preHookConfig.hookAddress,
            expectedRevertData,
            block.timestamp
        );

        // This should not revert due to allowHookFailure being true
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_allowPostUpdateHookFailure_reverts() public {
        // This test checks that if allowHookFailure is true, the PostUpdate hook failure does not revert.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 1_000_000,
            allowHookFailure: true
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        string memory expectedError = "PostUpdate hook failed";
        bytes memory expectedRevertData = abi.encodeWithSignature("Error(string)", expectedError);

        postHook.stubSetPostUpdateHookReverts(true, expectedError);

        vm.expectEmit(true, true, true, true);

        emit DataStreamsFeed.HookFailed(
            uint256(DataStreamsFeed.HookType.PostUpdate),
            postHookConfig.hookAddress,
            expectedRevertData,
            block.timestamp
        );

        // This should not revert due to allowHookFailure being true
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_allowPreAndPostUpdateHookFailure_reverts() public {
        // This test checks that if allowHookFailure is true for both hooks, both hook failures do not revert.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();
        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 1_000_000,
            allowHookFailure: true
        });

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 1_000_000,
            allowHookFailure: true
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);
        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        string memory expectedPreError = "PreUpdate hook failed";
        bytes memory expectedPreRevertData = abi.encodeWithSignature("Error(string)", expectedPreError);
        string memory expectedPostError = "PostUpdate hook failed";
        bytes memory expectedPostRevertData = abi.encodeWithSignature("Error(string)", expectedPostError);

        preHook.stubSetPreUpdateHookReverts(true, expectedPreError);
        postHook.stubSetPostUpdateHookReverts(true, expectedPostError);

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookFailed(
            uint256(DataStreamsFeed.HookType.PreUpdate),
            preHookConfig.hookAddress,
            expectedPreRevertData,
            block.timestamp
        );

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookFailed(
            uint256(DataStreamsFeed.HookType.PostUpdate),
            postHookConfig.hookAddress,
            expectedPostRevertData,
            block.timestamp
        );

        // This should not revert due to allowHookFailure being true for both hooks
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_allowPreUpdateHookFailure_outOfGas() public {
        // This test checks that if allowHookFailure is true, the PreUpdate hook failure does not revert even if it runs out of gas.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 1,
            allowHookFailure: true
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookFailed(
            uint256(DataStreamsFeed.HookType.PreUpdate),
            preHookConfig.hookAddress,
            "",
            block.timestamp
        );

        // This should not revert due to allowHookFailure being true
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_allowPostUpdateHookFailure_outOfGas() public {
        // This test checks that if allowHookFailure is true, the PostUpdate hook failure does not revert even if it runs out of gas.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 1,
            allowHookFailure: true
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookFailed(
            uint256(DataStreamsFeed.HookType.PostUpdate),
            postHookConfig.hookAddress,
            "",
            block.timestamp
        );

        // This should not revert due to allowHookFailure being true
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_allowPreAndPostUpdateHookFailure_outOfGas() public {
        // This test checks that if allowHookFailure is true for both hooks, both hook failures do not revert even if they run out of gas.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();
        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 1,
            allowHookFailure: true
        });

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 1,
            allowHookFailure: true
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);
        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookFailed(
            uint256(DataStreamsFeed.HookType.PreUpdate),
            preHookConfig.hookAddress,
            "",
            block.timestamp
        );

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.HookFailed(
            uint256(DataStreamsFeed.HookType.PostUpdate),
            postHookConfig.hookAddress,
            "",
            block.timestamp
        );

        // This should not revert due to allowHookFailure being true for both hooks
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_disallowPreUpdateHookFailure_reverts() public {
        // This test checks that if allowHookFailure is false, the PreUpdate hook failure reverts.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 1_000_000,
            allowHookFailure: false
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        string memory expectedError = "PreUpdate hook failed";
        bytes memory underlyingRevertData = abi.encodeWithSignature("Error(string)", expectedError);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            DataStreamsFeed.HookFailedError.selector,
            uint256(DataStreamsFeed.HookType.PreUpdate),
            preHookConfig.hookAddress,
            underlyingRevertData
        );

        preHook.stubSetPreUpdateHookReverts(true, expectedError);

        vm.expectRevert(expectedRevertData);

        // This should revert due to allowHookFailure being false
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_disallowPostUpdateHookFailure_reverts() public {
        // This test checks that if allowHookFailure is false, the PostUpdate hook failure reverts.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 1_000_000,
            allowHookFailure: false
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        string memory expectedError = "PostUpdate hook failed";
        bytes memory underlyingRevertData = abi.encodeWithSignature("Error(string)", expectedError);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            DataStreamsFeed.HookFailedError.selector,
            uint256(DataStreamsFeed.HookType.PostUpdate),
            postHookConfig.hookAddress,
            underlyingRevertData
        );

        postHook.stubSetPostUpdateHookReverts(true, expectedError);

        vm.expectRevert(expectedRevertData);

        // This should revert due to allowHookFailure being false
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_disallowPreUpdateHookFailure_outOfGas() public {
        // This test checks that if allowHookFailure is false, the PreUpdate hook failure reverts even if it runs out of gas.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PreUpdateHookStub preHook = new PreUpdateHookStub();

        DataStreamsFeed.Hook memory preHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(preHook),
            hookGasLimit: 1,
            allowHookFailure: false
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PreUpdate), preHookConfig);

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        bytes memory expectedRevertData = abi.encodeWithSelector(
            DataStreamsFeed.HookFailedError.selector,
            uint256(DataStreamsFeed.HookType.PreUpdate),
            preHookConfig.hookAddress,
            ""
        );

        vm.expectRevert(expectedRevertData);

        // This should revert due to allowHookFailure being false
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_disallowPostUpdateHookFailure_outOfGas() public {
        // This test checks that if allowHookFailure is false, the PostUpdate hook failure reverts even if it runs out of gas.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        PostUpdateHookStub postHook = new PostUpdateHookStub();

        DataStreamsFeed.Hook memory postHookConfig = DataStreamsFeed.Hook({
            hookAddress: address(postHook),
            hookGasLimit: 1,
            allowHookFailure: false
        });

        feed.setHookConfig(uint8(DataStreamsFeed.HookType.PostUpdate), postHookConfig);

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0));

        bytes memory expectedRevertData = abi.encodeWithSelector(
            DataStreamsFeed.HookFailedError.selector,
            uint256(DataStreamsFeed.HookType.PostUpdate),
            postHookConfig.hookAddress,
            ""
        );

        vm.expectRevert(expectedRevertData);
        // This should revert due to allowHookFailure being false
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_supportsInterface_IDataStreamsFeed() public {
        // This test checks that the contract supports the IDataStreamsFeed interface.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        assertTrue(
            feed.supportsInterface(type(IDataStreamsFeed).interfaceId),
            "Should support IDataStreamsFeed interface"
        );
    }

    function test_supportsInterface_AggregatorV2V3Interface() public {
        // This test checks that the contract supports the AggregatorV2V3Interface.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        assertTrue(
            feed.supportsInterface(type(AggregatorV2V3Interface).interfaceId),
            "Should support AggregatorV2V3Interface"
        );
    }

    function test_supportsInterface_AggregatorInterface() public {
        // This test checks that the contract supports the AggregatorInterface.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        assertTrue(feed.supportsInterface(type(AggregatorInterface).interfaceId), "Should support AggregatorInterface");
    }

    function test_supportsInterface_AggregatorV3Interface() public {
        // This test checks that the contract supports the AggregatorV3Interface.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        assertTrue(
            feed.supportsInterface(type(AggregatorV3Interface).interfaceId),
            "Should support AggregatorV3Interface"
        );
    }

    function test_supportsInterface_IAccessControlEnumerable() public {
        // This test checks that the contract supports the IAccessControlEnumerable interface.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        assertTrue(
            feed.supportsInterface(type(IAccessControlEnumerable).interfaceId),
            "Should support IAccessControlEnumerable interface"
        );
    }

    function test_supportsInterface_IAccessControl() public {
        // This test checks that the contract supports the IAccessControl interface.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        assertTrue(feed.supportsInterface(type(IAccessControl).interfaceId), "Should support IAccessControl interface");
    }

    function describe_latestAnswer_revertsWhenReportIsExpiredTest(uint32 secondsExpired) public {
        // This test checks that latestAnswer reverts when the report is expired.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp - 7200); // Valid from 2 hours ago
        uint32 observationsTimestamp = uint32(block.timestamp - 1); // Observations timestamp 1 second ago
        uint32 expiresAt = uint32(block.timestamp + 7200); // Expires in 2 hour ago

        bytes memory unverifiedReport = generateReportData(
            ETH_USD_V3.feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        vm.warp(expiresAt + secondsExpired); // Warp time to after expiration

        vm.expectRevert(
            abi.encodeWithSelector(DataStreamsFeed.ReportIsExpired.selector, expiresAt, uint32(block.timestamp))
        );
        feed.latestAnswer();
    }

    function test_latestAnswer_revertsWhenReportIsExpired_0secondsExpired() public {
        describe_latestAnswer_revertsWhenReportIsExpiredTest(0);
    }

    function test_latestAnswer_revertsWhenReportIsExpired_1secondExpired() public {
        describe_latestAnswer_revertsWhenReportIsExpiredTest(1);
    }

    function describe_latestRoundData_revertsWhenReportIsExpiredTest(uint32 secondsExpired) public {
        // This test checks that latestRoundData reverts when the report is expired.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price

        uint32 validFrom = uint32(block.timestamp - 7200); // Valid from 2 hours ago
        uint32 observationsTimestamp = uint32(block.timestamp - 1); // Observations timestamp 1 second ago
        uint32 expiresAt = uint32(block.timestamp + 7200); // Expires in 2 hour ago

        bytes memory unverifiedReport = generateReportData(
            ETH_USD_V3.feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        vm.warp(expiresAt + secondsExpired); // Warp time to after expiration

        vm.expectRevert(
            abi.encodeWithSelector(DataStreamsFeed.ReportIsExpired.selector, expiresAt, uint32(block.timestamp))
        );
        feed.latestRoundData();
    }

    function test_latestRoundData_revertsWhenReportIsExpired_0secondsExpired() public {
        describe_latestRoundData_revertsWhenReportIsExpiredTest(0);
    }

    function test_latestRoundData_revertsWhenReportIsExpired_1secondExpired() public {
        describe_latestRoundData_revertsWhenReportIsExpiredTest(1);
    }

    function test_getAnswer_revertsWhenRoundIdIsTooLarge() public {
        // Push a report to test for uint32 overflow (we test 2^32 + 1 - this should overflow to roundId=1)
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);
        bytes memory parameterPayload = abi.encode(address(0));

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        // This should revert because the roundId is too large (2^32 + 1)
        vm.expectRevert(abi.encodeWithSelector(DataStreamsFeed.MissingReport.selector));
        feed.getAnswer(2 ** 32 + 1);
    }

    function test_getTimestamp_revertsWhenRoundIdIsTooLarge() public {
        // Push a report to test for uint32 overflow (we test 2^32 + 1 - this should overflow to roundId=1)
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);
        bytes memory parameterPayload = abi.encode(address(0));

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        // This should revert because the roundId is too large (2^32 + 1)
        vm.expectRevert(abi.encodeWithSelector(DataStreamsFeed.MissingReport.selector));
        feed.getTimestamp(2 ** 32 + 1);
    }

    function test_getRoundData_revertsWhenRoundIdIsTooLarge() public {
        // Push a report to test for uint32 overflow (we test 2^32 + 1 - this should overflow to roundId=1)
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);
        bytes memory parameterPayload = abi.encode(address(0));

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        // This should revert because the roundId is too large (2^32 + 1)
        vm.expectRevert(abi.encodeWithSelector(DataStreamsFeed.MissingReport.selector));
        feed.getRoundData(2 ** 32 + 1);
    }

    function test_updateReport_revertsWhenUnauthorized() public {
        // This test checks that updateReport reverts when the caller is not authorized.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);
        bytes memory parameterPayload = abi.encode(address(0));
        bytes memory verifiedReport = verifierStub.verify(unverifiedReport, parameterPayload);

        bytes32 verifierRole = feed.REPORT_VERIFIER();

        address unauthorizedUser = address(0x456);
        vm.startPrank(unauthorizedUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                unauthorizedUser,
                verifierRole
            )
        );
        feed.updateReport(3, verifiedReport);
    }

    function test_updateReport_worksWhenAuthorized() public {
        // This test checks that updateReport works when the caller is authorized.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        int192 price = int192(int256((uint256(2000) * 10 ** ETH_USD_V3.decimals))); // Example price
        uint32 validFrom = uint32(block.timestamp - 3600); // Valid from 1 hour ago
        uint32 observationsTimestamp = uint32(block.timestamp - 1);
        uint32 expiresAt = uint32(block.timestamp + 7200); // Expires in

        bytes memory unverifiedReport = generateReportData(
            ETH_USD_V3.feedId,
            validFrom,
            observationsTimestamp,
            expiresAt,
            price,
            true
        );

        bytes memory parameterPayload = abi.encode(address(0));
        bytes memory verifiedReport = verifierStub.verify(unverifiedReport, parameterPayload);

        bytes32 verifierRole = feed.REPORT_VERIFIER();

        feed.grantRole(verifierRole, address(this));

        vm.expectEmit(true, true, true, true);
        emit DataStreamsFeed.ReportUpdated(
            ETH_USD_V3.feedId,
            address(this),
            ROUND_ID_FIRST,
            price,
            validFrom,
            observationsTimestamp,
            expiresAt,
            uint32(block.timestamp)
        );

        // This should not revert
        feed.updateReport(3, verifiedReport);

        // Verify that the report was updated correctly
        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) = feed
            .latestRoundData();
        assertEq(roundId, ROUND_ID_FIRST, "Round ID should be 1");
        assertEq(answer, price, "Latest answer should match the report price");
        assertEq(startedAt, observationsTimestamp, "Started at should match the report observations timestamp");
        assertEq(updatedAt, uint32(block.timestamp), "Updated at should match the current block timestamp");
        assertEq(answeredInRound, ROUND_ID_FIRST, "Answered in round should match the report round ID");
        assertEq(feed.latestAnswer(), price, "Latest answer should match the report price");
        assertEq(
            feed.latestTimestamp(),
            observationsTimestamp,
            "Latest timestamp should match the observations timestamp"
        );
        assertEq(feed.latestRound(), ROUND_ID_FIRST, "Latest round should be 1");
    }

    function test_verifyAndUpdateReport_handlesNoFeeToken() public {
        // This test checks that verifyAndUpdateReport works correctly when no fee token is provided.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        FeeManagerStub feeManagerStub = new FeeManagerStub();

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(address(0)); // No fee token provided

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_handlesNoRewardManager() public {
        // This test checks that verifyAndUpdateReport works correctly when no reward manager is provided.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        FakeErc20 fakeLink = new FakeErc20();

        FeeManagerStub feeManagerStub = new FeeManagerStub();

        feeManagerStub.setLinkAddress(address(fakeLink));

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(fakeLink);

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_approveLink() public {
        // This test checks that verifyAndUpdateReport approves LINK tokens correctly.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        FakeErc20 fakeLink = new FakeErc20();

        // Transfer some LINK to the feed
        fakeLink.transfer(address(feed), 100 * 10 ** fakeLink.decimals());

        FeeManagerStub feeManagerStub = new FeeManagerStub();
        RewardManagerStub rewardManagerStub = new RewardManagerStub();

        feeManagerStub.setLinkAddress(address(fakeLink));
        feeManagerStub.setRewardManager(address(rewardManagerStub));

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(fakeLink);

        vm.expectEmit({emitter: address(fakeLink)});
        emit IERC20.Approval(address(feed), address(rewardManagerStub), type(uint256).max);

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_feesAreCollected() public {
        // This test checks that fees are collected correctly during verifyAndUpdateReport.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        FakeErc20 fakeLink = new FakeErc20();

        // Transfer some LINK to the feed
        fakeLink.transfer(address(feed), 100 * 10 ** fakeLink.decimals());

        FeeManagerStub feeManagerStub = new FeeManagerStub();
        RewardManagerStub rewardManagerStub = new RewardManagerStub();

        feeManagerStub.setLinkAddress(address(fakeLink));
        feeManagerStub.setRewardManager(address(rewardManagerStub));

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(fakeLink);

        uint256 feeAmount = 1 * 10 ** fakeLink.decimals(); // Example fee amount

        feeManagerStub.setFee(address(fakeLink), feeAmount);

        uint256 initialFeedBalance = fakeLink.balanceOf(address(feed));
        uint256 initialRewardManagerBalance = fakeLink.balanceOf(address(rewardManagerStub));

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        uint256 finalFeedBalance = fakeLink.balanceOf(address(feed));
        uint256 finalRewardManagerBalance = fakeLink.balanceOf(address(rewardManagerStub));

        assertEq(finalFeedBalance, initialFeedBalance - feeAmount, "Feed balance should decrease by the fee amount");
        assertEq(
            finalRewardManagerBalance,
            initialRewardManagerBalance + feeAmount,
            "Reward manager balance should increase by the fee amount"
        );
    }

    function test_verifyAndUpdateReport_revertsIfTheWrongFeeTokenIsProvided() public {
        // This test checks that verifyAndUpdateReport reverts if the wrong fee token is provided.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        FakeErc20 fakeLink = new FakeErc20();
        FakeErc20 fakeUsdc = new FakeErc20();

        // Transfer some LINK to the feed
        fakeLink.transfer(address(feed), 100 * 10 ** fakeLink.decimals());

        // Transfer some USDC to the feed
        fakeUsdc.transfer(address(feed), 100 * 10 ** fakeUsdc.decimals());

        FeeManagerStub feeManagerStub = new FeeManagerStub();
        RewardManagerStub rewardManagerStub = new RewardManagerStub();

        feeManagerStub.setLinkAddress(address(fakeLink));
        feeManagerStub.setRewardManager(address(rewardManagerStub));

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(fakeUsdc); // Wrong fee token

        uint256 feeAmount = 1 * 10 ** fakeLink.decimals(); // Example fee amount

        feeManagerStub.setFee(address(fakeLink), feeAmount);

        vm.expectRevert();

        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);
    }

    function test_verifyAndUpdateReport_feesAreCollectedTwiceAfterTwoVerifies() public {
        // This test checks that fees are collected correctly during two consecutive verifyAndUpdateReport calls.
        DataStreamsFeed feed = new DataStreamsFeed(
            address(verifierStub),
            ETH_USD_V3.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        FakeErc20 fakeLink = new FakeErc20();

        // Transfer some LINK to the feed
        fakeLink.transfer(address(feed), 100 * 10 ** fakeLink.decimals());

        FeeManagerStub feeManagerStub = new FeeManagerStub();
        RewardManagerStub rewardManagerStub = new RewardManagerStub();

        feeManagerStub.setLinkAddress(address(fakeLink));
        feeManagerStub.setRewardManager(address(rewardManagerStub));

        VerifierStub(address(verifierStub)).setFeeManager(address(feeManagerStub));

        bytes memory unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        bytes memory parameterPayload = abi.encode(fakeLink);

        uint256 feeAmount = 1 * 10 ** fakeLink.decimals(); // Example fee amount

        feeManagerStub.setFee(address(fakeLink), feeAmount);

        uint256 initialFeedBalance = fakeLink.balanceOf(address(feed));
        uint256 initialRewardManagerBalance = fakeLink.balanceOf(address(rewardManagerStub));

        // First verifyAndUpdateReport call
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        uint256 firstFeedBalanceAfterFirstCall = fakeLink.balanceOf(address(feed));
        uint256 firstRewardManagerBalanceAfterFirstCall = fakeLink.balanceOf(address(rewardManagerStub));

        assertEq(
            firstFeedBalanceAfterFirstCall,
            initialFeedBalance - feeAmount,
            "Feed balance should decrease by the fee amount after first call"
        );
        assertEq(
            firstRewardManagerBalanceAfterFirstCall,
            initialRewardManagerBalance + feeAmount,
            "Reward manager balance should increase by the fee amount after first call"
        );

        vm.warp(block.timestamp + 1); // Simulate time passing for the second call

        // Reset the unverified report to simulate a new report
        unverifiedReport = generateSimpleReportData(ETH_USD_V3.feedId, true);

        // Second verifyAndUpdateReport call
        feed.verifyAndUpdateReport(unverifiedReport, parameterPayload);

        uint256 finalFeedBalance = fakeLink.balanceOf(address(feed));
        uint256 finalRewardManagerBalance = fakeLink.balanceOf(address(rewardManagerStub));

        assertEq(
            finalFeedBalance,
            firstFeedBalanceAfterFirstCall - feeAmount,
            "Feed balance should decrease by the fee amount after second call"
        );
        assertEq(
            finalRewardManagerBalance,
            firstRewardManagerBalanceAfterFirstCall + feeAmount,
            "Reward manager balance should increase by the fee amount after second call"
        );

        uint256 finalAllowance = fakeLink.allowance(address(feed), address(rewardManagerStub));
        assertEq(finalAllowance, type(uint256).max, "Allowance should remain max after two calls");
    }
}
