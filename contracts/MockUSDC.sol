// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockUSDC
 * @notice Simple 6-decimal test token mimicking USDC for local Anvil and Sepolia testnet testing.
 */
contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USD Coin", "mUSDC") {
        // Mint 1,000,000 mUSDC to deployer for testing
        _mint(msg.sender, 1_000_000 * 10 ** decimals());
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
