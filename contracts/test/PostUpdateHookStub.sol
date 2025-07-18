// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IDataStreamsPostUpdateHook} from "../feed/hooks/IDataStreamsPostUpdateHook.sol";

contract PostUpdateHookStub is IDataStreamsPostUpdateHook, IERC165 {
    uint256 public postUpdateHookCallTimes = 0;

    bool postUpdateHookReverts = false;
    string postUpdateHookRevertMessage = "";

    bytes32 public postLastFeedId;
    uint32 public postLastRoundId;
    int192 public postLastPrice;
    uint32 public postLastObservationTimestamp;
    uint32 public postLastExpiresAt;
    uint32 public postLastUpdatedAt;

    function onPostReportUpdate(
        bytes32 feedId,
        uint32 roundId,
        int192 price,
        uint32 observationTimestamp,
        uint32 expiresAt,
        uint32 updatedAt
    ) external {
        ++postUpdateHookCallTimes;

        postLastFeedId = feedId;
        postLastRoundId = roundId;
        postLastPrice = price;
        postLastObservationTimestamp = observationTimestamp;
        postLastExpiresAt = expiresAt;
        postLastUpdatedAt = updatedAt;

        if (postUpdateHookReverts) {
            revert(postUpdateHookRevertMessage);
        }
    }

    function supportsInterface(bytes4 interfaceId) public pure virtual returns (bool) {
        return interfaceId == type(IDataStreamsPostUpdateHook).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    function stubSetPostUpdateHookReverts(bool reverts, string memory revertMessage) external {
        postUpdateHookReverts = reverts;
        postUpdateHookRevertMessage = revertMessage;
    }
}
