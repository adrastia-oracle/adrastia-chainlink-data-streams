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
import {AdrastiaDataStreamsUpdater} from "../../../updater/AdrastiaDataStreamsUpdater.sol";
import {console2} from "forge-std/console2.sol";

contract UpdaterForkTest is Test, FeedConstants, FeedDataFixture {
    struct ReportData {
        bytes32 feedId;
        int192 price;
        uint32 validFromTimestamp;
        uint32 observationsTimestamp;
        uint32 expiresAt;
        bytes rawReport;
    }

    string internal ETH_MAINNET_RPC_URL = vm.envString("ETHEREUM_MAINNET_RPC_URL");
    uint256 internal ETH_MAINNET_BLOCK_NUMBER = 22949499;
    address internal ETH_MAINNET_VERIFIER_PROXY_ADDRESS = 0x5A1634A86e9b7BfEf33F0f3f3EA3b1aBBc4CC85F;

    string internal BASE_MAINNET_RPC_URL = vm.envString("BASE_MAINNET_RPC_URL");
    uint256 internal BASE_MAINNET_BLOCK_NUMBER = 33046512; // Jul-18-2025 11:46:11 PM +UTC
    address internal BASE_MAINNET_VERIFIER_PROXY_ADDRESS = 0xDE1A28D87Afd0f546505B28AB50410A5c3a7387a;
    address internal BASE_MAINNET_LINK_ADDRESS = 0x88Fb150BDc53A65fe94Dea0c9BA0a6dAf8C6e196;
    address internal BASE_MAINNET_LINK_HOLDER_ADDRESS = 0xf4bAb6A129164aBa9B113cB96BA4266dF49f8743;

    ReportData internal ETH_USD_ReportData =
        ReportData({
            feedId: 0x000362205e10b3a147d02792eccee483dca6c7b44ecce7012cb8c6e0b68b3ae9,
            price: 3541546843929323200000,
            validFromTimestamp: 1752882370, // Jul-18-2025 11:46:10 PM +UTC
            observationsTimestamp: 1752882370,
            expiresAt: 1755474370,
            rawReport: hex"00094baebfda9b87680d8e59aa20a3e565126640ee7caeab3cd965e5568b17ee00000000000000000000000000000000000000000000000000000000007c8191000000000000000000000000000000000000000000000000000000040000000100000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000030001010100010100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120000362205e10b3a147d02792eccee483dca6c7b44ecce7012cb8c6e0b68b3ae900000000000000000000000000000000000000000000000000000000687adcc200000000000000000000000000000000000000000000000000000000687adcc20000000000000000000000000000000000000000000000000000522da558340e000000000000000000000000000000000000000000000000003fec89a74d013c0000000000000000000000000000000000000000000000000000000068a269c20000000000000000000000000000000000000000000000bffcd5eaa265175e000000000000000000000000000000000000000000000000bffc910d5497f7b1500000000000000000000000000000000000000000000000c0003be7d9f83f339000000000000000000000000000000000000000000000000000000000000000066db21d04a6e703b9d938cd376d4d409473b998ad544864869ba3323739a39093a28c003121ea69cfd59195686b98da1d61691bb952057d7014ccebf5cbabc0ba364a74c9bc6017c98cf60ca2fb5f8edc2334f0fffabae5247c963b53ddc05238e6a0a555dbc825ec3efaec08c35128a5f1a60fa6f4f4976e6bf68bc23e2731342533e2c22fb1dd58af005a234397e02a091cd7fb18365ad421a9d885c19b8719106a4beac4f075b86c716ed87b910a20c7c4e6d99dcae1f8988f935370dca42b00000000000000000000000000000000000000000000000000000000000000065092ca48b38a38a2f230d2ebd86a85cacf08eecdcb7189ad67e531b174c9d508389e1015ee976dd848263999768aed206a68964df838abcdb70c44274cc715b0498797d5bfa68ad7d15fb20cb61eb9269b82070f3dad63ddb00a8f048b69ea3b1330e9078410db5126e687b18a2b0cdbf8e073eeb299e6f399f013c974de439165dbb44f3ef2cbfe2d01ea4d09e39a02937cd03a77a9249bc9db6ebb5ee9196012f092b200c846357adefce098c829fe7176cd713895f6734917c22844fb6b54"
        });

    uint256 ethMainnetFork;
    uint256 baseMainnetFork;

    function setUp() public {
        ethMainnetFork = vm.createFork(ETH_MAINNET_RPC_URL, ETH_MAINNET_BLOCK_NUMBER);
        baseMainnetFork = vm.createFork(BASE_MAINNET_RPC_URL, BASE_MAINNET_BLOCK_NUMBER);
    }

    function test_performUpkeep_updatesAndPaysFees() public {
        vm.selectFork(baseMainnetFork);

        ReportData memory reportData = ETH_USD_ReportData;

        DataStreamsFeed feed = new DataStreamsFeed(
            BASE_MAINNET_VERIFIER_PROXY_ADDRESS,
            reportData.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            BASE_MAINNET_VERIFIER_PROXY_ADDRESS,
            address(this),
            address(this)
        );

        {
            bytes32 updaterConfigAdminRole = updater.CONFIG_ADMIN();
            bytes32 updaterOracleUpdaterRole = updater.ORACLE_UPDATER();
            updater.grantRole(updaterConfigAdminRole, address(this));
            updater.grantRole(updaterOracleUpdaterRole, address(this));
        }

        // Register the feed
        updater.registerFeed(reportData.feedId, address(feed));

        // Grant the verifier role to the updater
        {
            bytes32 reportVerifierRole = feed.REPORT_VERIFIER();
            feed.grantRole(reportVerifierRole, address(updater));
        }

        // Add LINK to the updater
        IERC20 linkToken = IERC20(BASE_MAINNET_LINK_ADDRESS);
        vm.startPrank(BASE_MAINNET_LINK_HOLDER_ADDRESS);
        linkToken.transfer(address(updater), 100e18); // Transfer 100 LINK to the updater
        vm.stopPrank();

        uint256 linkBalanceBefore = linkToken.balanceOf(address(updater));

        // Check that the report was stored correctly
        uint32 expectedRoundId = ROUND_ID_FIRST;

        vm.expectEmit(true, true, true, true, address(feed));

        emit AggregatorInterface.AnswerUpdated(reportData.price, reportData.observationsTimestamp, block.timestamp);

        vm.expectEmit(true, true, true, true, address(feed));

        emit DataStreamsFeed.ReportUpdated(
            ETH_USD_V3.feedId,
            address(updater),
            expectedRoundId,
            reportData.price,
            reportData.validFromTimestamp,
            reportData.observationsTimestamp,
            reportData.expiresAt,
            uint32(block.timestamp)
        );

        vm.expectEmit(true, true, true, true, address(updater));

        emit AdrastiaDataStreamsUpdater.FeedUpdatePerformed(reportData.feedId, address(feed), block.timestamp);

        {
            // Verify and store the report
            bytes[] memory reports = new bytes[](1);
            reports[0] = reportData.rawReport;

            updater.performUpkeep(abi.encode(reports));
        }

        uint256 linkBalanceAfter = linkToken.balanceOf(address(updater));
        assertLt(linkBalanceAfter, linkBalanceBefore, "Updater should have paid fees in LINK");

        assertEq(feed.latestAnswer(), reportData.price, "Latest answer should match the report price");
        assertEq(
            feed.latestTimestamp(),
            reportData.observationsTimestamp,
            "Latest timestamp should match the report observationsTimestamp"
        );
        assertEq(feed.latestRound(), expectedRoundId, "Latest round should equal 1");

        assertEq(
            feed.getAnswer(expectedRoundId),
            reportData.price,
            "Answer for the first round should match the report price"
        );
        assertEq(
            feed.getTimestamp(expectedRoundId),
            reportData.observationsTimestamp,
            "Timestamp for the first round should match the report observationsTimestamp"
        );
        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) = feed
            .getRoundData(expectedRoundId);

        assertEq(roundId, expectedRoundId, "Round ID should match the expected round ID");
        assertEq(answer, reportData.price, "Answer for the first round should match the report price");
        assertEq(
            startedAt,
            reportData.observationsTimestamp,
            "Started at should match the report observationsTimestamp"
        );
        assertEq(updatedAt, block.timestamp, "Updated at should match the current timestamp");
        assertEq(answeredInRound, expectedRoundId, "Answered in round should match the expected round ID");

        // Check latestRoundData
        (roundId, answer, startedAt, updatedAt, answeredInRound) = feed.latestRoundData();

        assertEq(roundId, expectedRoundId, "Latest round ID should match the expected round ID");
        assertEq(answer, reportData.price, "Latest answer should match the report price");
        assertEq(
            startedAt,
            reportData.observationsTimestamp,
            "Latest started at should match the report observationsTimestamp"
        );
        assertEq(updatedAt, block.timestamp, "Latest updated at should match the current timestamp");
        assertEq(answeredInRound, expectedRoundId, "Latest answered in round should match the expected round ID");
    }

    function test_performUpkeep_updatesWithoutFees() public {
        vm.selectFork(ethMainnetFork);

        assertEq(
            IVerifierProxy(ETH_MAINNET_VERIFIER_PROXY_ADDRESS).s_feeManager(),
            address(0),
            "Fee manager should be unset"
        );

        ReportData memory reportData = ETH_USD_ReportData;

        DataStreamsFeed feed = new DataStreamsFeed(
            ETH_MAINNET_VERIFIER_PROXY_ADDRESS,
            reportData.feedId,
            ETH_USD_V3.decimals,
            ETH_USD_V3.description
        );

        AdrastiaDataStreamsUpdater updater = new AdrastiaDataStreamsUpdater(
            ETH_MAINNET_VERIFIER_PROXY_ADDRESS,
            address(this),
            address(this)
        );

        {
            bytes32 updaterConfigAdminRole = updater.CONFIG_ADMIN();
            bytes32 updaterOracleUpdaterRole = updater.ORACLE_UPDATER();
            updater.grantRole(updaterConfigAdminRole, address(this));
            updater.grantRole(updaterOracleUpdaterRole, address(this));
        }

        // Register the feed
        updater.registerFeed(reportData.feedId, address(feed));

        // Grant the verifier role to the updater
        {
            bytes32 reportVerifierRole = feed.REPORT_VERIFIER();
            feed.grantRole(reportVerifierRole, address(updater));
        }

        // Check that the report was stored correctly
        uint32 expectedRoundId = ROUND_ID_FIRST;

        vm.expectEmit(true, true, true, true, address(feed));

        emit AggregatorInterface.AnswerUpdated(reportData.price, reportData.observationsTimestamp, block.timestamp);

        vm.expectEmit(true, true, true, true, address(feed));

        emit DataStreamsFeed.ReportUpdated(
            ETH_USD_V3.feedId,
            address(updater),
            expectedRoundId,
            reportData.price,
            reportData.validFromTimestamp,
            reportData.observationsTimestamp,
            reportData.expiresAt,
            uint32(block.timestamp)
        );

        vm.expectEmit(true, true, true, true, address(updater));

        emit AdrastiaDataStreamsUpdater.FeedUpdatePerformed(reportData.feedId, address(feed), block.timestamp);

        {
            // Verify and store the report
            bytes[] memory reports = new bytes[](1);
            reports[0] = reportData.rawReport;

            updater.performUpkeep(abi.encode(reports));
        }

        assertEq(feed.latestAnswer(), reportData.price, "Latest answer should match the report price");
        assertEq(
            feed.latestTimestamp(),
            reportData.observationsTimestamp,
            "Latest timestamp should match the report observationsTimestamp"
        );
        assertEq(feed.latestRound(), expectedRoundId, "Latest round should equal 1");

        assertEq(
            feed.getAnswer(expectedRoundId),
            reportData.price,
            "Answer for the first round should match the report price"
        );
        assertEq(
            feed.getTimestamp(expectedRoundId),
            reportData.observationsTimestamp,
            "Timestamp for the first round should match the report observationsTimestamp"
        );
        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) = feed
            .getRoundData(expectedRoundId);

        assertEq(roundId, expectedRoundId, "Round ID should match the expected round ID");
        assertEq(answer, reportData.price, "Answer for the first round should match the report price");
        assertEq(
            startedAt,
            reportData.observationsTimestamp,
            "Started at should match the report observationsTimestamp"
        );
        assertEq(updatedAt, block.timestamp, "Updated at should match the current timestamp");
        assertEq(answeredInRound, expectedRoundId, "Answered in round should match the expected round ID");

        // Check latestRoundData
        (roundId, answer, startedAt, updatedAt, answeredInRound) = feed.latestRoundData();

        assertEq(roundId, expectedRoundId, "Latest round ID should match the expected round ID");
        assertEq(answer, reportData.price, "Latest answer should match the report price");
        assertEq(
            startedAt,
            reportData.observationsTimestamp,
            "Latest started at should match the report observationsTimestamp"
        );
        assertEq(updatedAt, block.timestamp, "Latest updated at should match the current timestamp");
        assertEq(answeredInRound, expectedRoundId, "Latest answered in round should match the expected round ID");
    }
}
