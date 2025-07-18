// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {PreUpdateHookStub} from "./PreUpdateHookStub.sol";
import {PostUpdateHookStub} from "./PostUpdateHookStub.sol";

contract UpdateHookStub is PreUpdateHookStub, PostUpdateHookStub {
    function supportsInterface(
        bytes4 interfaceId
    ) public pure override(PreUpdateHookStub, PostUpdateHookStub) returns (bool) {
        return PreUpdateHookStub.supportsInterface(interfaceId) || PostUpdateHookStub.supportsInterface(interfaceId);
    }
}
