// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IDataStreamsFeed {
    function feedId() external view returns (bytes32);

    function updateReport(uint16 reportVersion, bytes calldata verifiedReportData) external;
}
