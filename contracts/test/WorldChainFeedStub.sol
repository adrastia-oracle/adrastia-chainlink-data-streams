// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FeedStub} from "./FeedStub.sol";
import {IWorldChainFeed} from "../updater/AdrastiaWorldChainDataStreamsUpdater.sol";

contract WorldChainFeedStub is FeedStub, IWorldChainFeed {
    bytes32 public immutable override FEED_ID;

    constructor(
        address verifierProxy_,
        bytes32 _feedId,
        uint8 _decimals,
        string memory _description
    ) FeedStub(verifierProxy_, _feedId, _decimals, _description) {
        FEED_ID = _feedId;
    }

    function feedId() public view override returns (bytes32) {
        revert("This is not implemented in world chain feeds");
    }

    function updatePriceData(
        bytes memory verifyReportRequest,
        bytes memory parameterPayload
    ) external returns (bytes memory) {
        this.verifyAndUpdateReport(verifyReportRequest, parameterPayload);

        return hex"";
    }

    function updateReport(
        bytes memory verifyReportRequest,
        bytes memory parameterPayload
    ) external returns (bytes memory) {
        revert("This function is not implemented in world chain feeds");
    }
}
