// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import './lib/SafeERC20.sol';
import '@openzeppelin/contracts/access/AccessControl.sol';
import '@openzeppelin/contracts/token/ERC20/IERC20.sol';

interface IBurnableErc20 is IERC20 {
    function burn(uint256 amount) external;
}

interface IUniswapV2Router02 {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}



/** @title DaiBasedREQBurner
 * @notice A contract to burn REQ tokens from DAI.
 * @dev All DAIs sent to this contract can only be exchanged for REQs that are then burnt, using Uniswap.
 */
contract ERC20toREQBurner is AccessControl {
    using SafeERC20 for IERC20;

    bytes32 public constant CHANGERATE_ROLE = keccak256("CHANGERATE_ROLE");

    // TODO: use this instead in prod: address constant REQ_ADDRESS = 0x8f8221aFbB33998d8584A2B05749bA73c37a938a;
    address public immutable REQ_ADDRESS;

    uint256 public foundationRateNumerator;
    uint256 public foundationRateDenominator;
    address public withdrawAddress;
    // swap router used to convert LOCKED into BURNABLE tokens
    IUniswapV2Router02 public swapRouter;

    /**
     * @notice Constructor of the ERC20 to REQ burner
     * @param _swapRouterAddress address of the uniswap token router (which follow the same method signature ).
     * @param _reqTokenAddress address of the REQ token contract (TODO: Remove for prod)
     */
    // TODO: use this in prod: constructor(address _swapRouterAddress) public {
    constructor(address _swapRouterAddress, address _reqTokenAddress) public {
        require(_swapRouterAddress != address(0), "The swap router address should not be 0");

        // TODO: to be removed in prod
        REQ_ADDRESS = _reqTokenAddress;
        // -------------------------------------

        swapRouter = IUniswapV2Router02(_swapRouterAddress);
                
        // Grant the contract deployer the default admin role
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        // Grant the contract deployer the CHANGERATE_ROLE
        _grantRole(CHANGERATE_ROLE, msg.sender);
    }

    function setFoundationRate(uint256 _numerator, uint256 _denominator) 
        external 
        onlyRole(CHANGERATE_ROLE) 
    {
        require(_denominator != 0 || _numerator == 0, "Denominator cannot be zero if numerator is not 0");
        foundationRateNumerator = _numerator;
        foundationRateDenominator = _denominator;
    }

    /**
     * @notice Transfer the CHANGERATE_ROLE from one address to another
     * @param _from Address to revoke the role from
     * @param _to Address to grant the role to
     * @dev Only accounts with DEFAULT_ADMIN_ROLE can call this function
     */
    function transferChangeRateRole(
        address _from, 
        address _to
    ) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        require(hasRole(CHANGERATE_ROLE, _from), "From address does not have CHANGERATE_ROLE");
        
        // Revoke the role from the current holder
        _revokeRole(CHANGERATE_ROLE, _from);
        
        // Grant the role to the new holder
        _grantRole(CHANGERATE_ROLE, _to);
    }

    /**
     * @notice Set the withdraw address where foundation rate portion will be sent
     * @param _withdrawAddress Address to receive the foundation rate portion
     * @dev Only accounts with DEFAULT_ADMIN_ROLE can call this function
     */
    function setWithdrawAddress(address _withdrawAddress) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        withdrawAddress = _withdrawAddress;
    }

    ///@dev Swap the whole amount owned by this contract of a token to REQ
    ///@param _path Uniswap path of ERC20 tokens to swap to REQ. 
    ///             The first address is the token to swap and the last should be REQ.
    ///@param _minReq  min REQ token expected to be received.
    ///@param _deadline  maximum timestamp to accept the trade from the router (default is 1000 seconds from now)
    function swapToReq(
        address[] memory _path,
        uint _minReq,  
        uint256 _deadline)
        onlyRole(DEFAULT_ADMIN_ROLE)
        external
        returns(uint)
    {
        require(_path[_path.length - 1] == REQ_ADDRESS, "The last path element must be the REQ address");
        require(_path.length > 1, "The path must have at least 2 elements");

        // TODO: Should we allow it?
        require(_path[0] != REQ_ADDRESS, "The first path element must NOT be the REQ address");

        IERC20 tokenToSwap = IERC20(_path[0]);
        // Get the amount to swap (aka the amount owned by this contract)
        uint amountToConvert = tokenToSwap.balanceOf(address(this));
        
        // Approve the swap router to spend the token to swap
        if(tokenToSwap.allowance(address(this), address(swapRouter)) < amountToConvert) {
            tokenToSwap.approve(address(swapRouter), 2**256 - 1);
        }

        // Set the default deadline
        if (_deadline == 0) {
            _deadline = block.timestamp + 1000;
        }

        // Do the swap and get the amount of REQ purchased to return it
        return swapRouter.swapExactTokensForTokens(
          amountToConvert,
          _minReq,
          _path,
          address(this),
          _deadline
        )[_path.length - 1];
    }

    ///@dev Distribute REQ tokens according to foundation rate and burn the rest
    ///@return burnedAmount The amount of REQ tokens burned
    ///@return withdrawnAmount The amount of REQ tokens sent to withdraw address
    function withdrawAndburn()
        onlyRole(DEFAULT_ADMIN_ROLE)
        external
        returns(uint burnedAmount, uint withdrawnAmount)
    {
        IBurnableErc20 req = IBurnableErc20(REQ_ADDRESS);
        uint totalReq = req.balanceOf(address(this));

        // Calculate amounts based on foundation rate
        if (foundationRateDenominator > 0 && withdrawAddress != address(0)) {
            withdrawnAmount = (totalReq * foundationRateNumerator) / foundationRateDenominator;
            burnedAmount = totalReq - withdrawnAmount;
            
            // Send foundation portion to withdraw address
            req.transfer(withdrawAddress, withdrawnAmount);
            
            req.burn(burnedAmount);
            
        } else {
            // If no foundation rate set or no withdraw address, burn everything
            burnedAmount = totalReq;
            withdrawnAmount = 0;
            req.burn(burnedAmount);
        }
    }
}