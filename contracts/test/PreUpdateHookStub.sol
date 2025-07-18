// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IDataStreamsPreUpdateHook} from "../feed/hooks/IDataStreamsPreUpdateHook.sol";

contract PreUpdateHookStub is IDataStreamsPreUpdateHook, IERC165 {
    uint256 public preUpdateHookCallTimes = 0;

    bool preUpdateHookReverts = false;
    string preUpdateHookRevertMessage = "";

    bytes32 public preLastFeedId;
    uint32 public preLastRoundId;
    int192 public preLastPrice;
    uint32 public preLastObservationTimestamp;
    uint32 public preLastExpiresAt;
    uint32 public preLastUpdatedAt;

    function onPreReportUpdate(
        bytes32 feedId,
        uint32 roundId,
        int192 price,
        uint32 observationTimestamp,
        uint32 expiresAt,
        uint32 updatedAt
    ) external {
        ++preUpdateHookCallTimes;

        preLastFeedId = feedId;
        preLastRoundId = roundId;
        preLastPrice = price;
        preLastObservationTimestamp = observationTimestamp;
        preLastExpiresAt = expiresAt;
        preLastUpdatedAt = updatedAt;

        if (preUpdateHookReverts) {
            revert(preUpdateHookRevertMessage);
        }
    }

    function supportsInterface(bytes4 interfaceId) public pure virtual returns (bool) {
        return interfaceId == type(IDataStreamsPreUpdateHook).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    function stubSetPreUpdateHookReverts(bool reverts, string memory revertMessage) external {
        preUpdateHookReverts = reverts;
        preUpdateHookRevertMessage = revertMessage;
    }
}
