// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Roles {
    /**
     * @notice The role hash for the admin. Accounts with this role can manage the role and sub-roles.
     */
    bytes32 public constant ADMIN = keccak256("ADMIN_ROLE");

    /**
     * @notice The role hash for the report verifier. Accounts with this role can pass verified reports to the contract
     * and update the latest report. Reports are expected to be verified by the report verifier before being passed to
     * this contract.
     *
     * This role is not required when using the `verifyAndUpdateReport` function, as that function will verify the
     * report before updating it.
     */
    bytes32 public constant REPORT_VERIFIER = keccak256("REPORT_VERIFIER_ROLE");

    /**
     * @notice The role hash for the update pause admin. Accounts with this role can pause and unpause the update
     * functionality of the contract. This is useful for emergency situations or maintenance.
     */
    bytes32 public constant UPDATE_PAUSE_ADMIN = keccak256("UPDATE_PAUSE_ADMIN_ROLE");
}
