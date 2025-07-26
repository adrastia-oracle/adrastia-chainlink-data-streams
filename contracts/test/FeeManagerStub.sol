// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {IFeeManager} from "../vendor/IFeeManager.sol";
import {Common} from "../vendor/Common.sol";

contract FeeManagerStub is IFeeManager {
    address internal linkAddress;
    address internal rewardManager;

    address internal feeAsset;
    uint256 internal feeAmount;

    function getFeeAndReward(
        address /* subscriber */,
        bytes memory /* unverifiedReport */,
        address quoteAddress
    ) external view returns (Common.Asset memory, Common.Asset memory, uint256) {
        if (quoteAddress != linkAddress) {
            revert("FeeManagerStub: quote address does not match fee manager's link address");
        }

        Common.Asset memory fee = Common.Asset({assetAddress: feeAsset, amount: feeAmount});

        Common.Asset memory reward = Common.Asset({
            assetAddress: feeAsset,
            amount: feeAmount // Example reward amount
        });

        return (fee, reward, 0); // No discount for simplicity
    }

    function i_linkAddress() external view returns (address) {
        return linkAddress;
    }

    function i_nativeAddress() external view returns (address) {}

    function i_rewardManager() external view returns (address) {
        return rewardManager;
    }

    function setLinkAddress(address _linkAddress) external {
        linkAddress = _linkAddress;
    }

    function setRewardManager(address _rewardManager) external {
        rewardManager = _rewardManager;
    }

    function setFee(address _feeAsset, uint256 _feeAmount) external {
        feeAsset = _feeAsset;
        feeAmount = _feeAmount;
    }
}
