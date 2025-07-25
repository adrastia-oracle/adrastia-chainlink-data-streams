// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8;

import {AdrastiaDataStreamsUpdater} from "../updater/AdrastiaDataStreamsUpdater.sol";

contract UpdaterStub is AdrastiaDataStreamsUpdater {
    constructor(
        address _verifierProxy,
        address initialAdmin,
        address initialUpdaterAdmin
    ) AdrastiaDataStreamsUpdater(_verifierProxy, initialAdmin, initialUpdaterAdmin) {}

    function stubCalculateChange(int256 a, int256 b) external pure returns (uint256 change, bool maximalChange) {
        return calculateChange(a, b);
    }
}
