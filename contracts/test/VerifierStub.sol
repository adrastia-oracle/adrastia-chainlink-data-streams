// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IVerifierProxy} from "../vendor/IVerifierProxy.sol";
import {DataStreamsStructs} from "../vendor/DataStreamsStructs.sol";
import {FeedDataFixture} from "./FeedDataFixture.sol";
import {IFeeManager} from "../vendor/IFeeManager.sol";
import {Common} from "../vendor/Common.sol";
import {RewardManagerStub} from "./RewardManagerStub.sol";

contract VerifierStub is IVerifierProxy, DataStreamsStructs, FeedDataFixture {
    address internal _feeManager;

    constructor() {}

    /// @inheritdoc IVerifierProxy
    function verify(
        bytes calldata payload,
        bytes calldata parameterPayload
    ) external payable override returns (bytes memory) {
        if (_feeManager != address(0)) {
            address linkAddress = IFeeManager(_feeManager).i_linkAddress();
            address rewardManager = IFeeManager(_feeManager).i_rewardManager();

            if (linkAddress != address(0) && rewardManager != address(0)) {
                address providedLinkAddress = abi.decode(parameterPayload, (address));
                if (providedLinkAddress != linkAddress) {
                    revert("VerifierStub: provided link address does not match fee manager's link address");
                }

                (Common.Asset memory fee, , ) = IFeeManager(_feeManager).getFeeAndReward(
                    msg.sender,
                    payload,
                    linkAddress
                );

                if (fee.amount > 0) {
                    RewardManagerStub(rewardManager).collectFee(linkAddress, msg.sender, fee.amount);
                }
            }
        }

        // Decode the payload as (bytes32[3], bytes)
        (bytes32[3] memory metadata, bytes memory rawData) = abi.decode(payload, (bytes32[3], bytes));

        if (metadata[0] != FEED_SIGNED) {
            revert("REPORT_NOT_SIGNED");
        }

        // Parse the 2-byte version manually
        uint16 version = (uint16(uint8(rawData[0])) << 8) | uint16(uint8(rawData[1]));

        // Slice the remaining bytes to get the report body
        bytes memory reportBytes;

        assembly {
            let len := sub(mload(rawData), 2)
            reportBytes := mload(0x40)
            mstore(reportBytes, len)
            let src := add(add(rawData, 0x20), 2)
            let dest := add(reportBytes, 0x20)
            for {
                let i := 0
            } lt(i, len) {
                i := add(i, 0x20)
            } {
                mstore(add(dest, i), mload(add(src, i)))
            }
            mstore(0x40, add(dest, len))
        }

        // Decode report based on version
        if (version == 4) {
            ReportV4 memory report = abi.decode(reportBytes, (ReportV4));
            return abi.encode(report);
        } else if (version == 3) {
            ReportV3 memory report = abi.decode(reportBytes, (ReportV3));
            return abi.encode(report);
        } else if (version == 2) {
            ReportV2 memory report = abi.decode(reportBytes, (ReportV2));
            return abi.encode(report);
        } else if (version == UNSUPPORTED_REPORT_VERSION) {
            return reportBytes;
        } else {
            revert("VerifierStub: unsupported version");
        }
    }

    /// @inheritdoc IVerifierProxy
    function verifyBulk(
        bytes[] calldata payloads,
        bytes calldata parameterPayload
    ) external payable override returns (bytes[] memory verifiedReports) {
        uint256 len = payloads.length;
        verifiedReports = new bytes[](len);

        for (uint256 i = 0; i < len; ++i) {
            // Call verify() for each entry
            verifiedReports[i] = this.verify(payloads[i], parameterPayload);
        }
    }

    /// @inheritdoc IVerifierProxy
    function s_feeManager() external view override returns (address) {
        return _feeManager;
    }

    /// @notice Set the fee manager
    function setFeeManager(address newFeeManager) external {
        _feeManager = newFeeManager;
    }
}
