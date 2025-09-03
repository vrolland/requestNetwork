// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import '@openzeppelin/contracts/access/AccessControl.sol';

/**
 * @title ERC20RequestFeeProxyMinMaxMap
 * @notice This contract performs an ERC20 token transfer, with a Fee sent to a third address and stores a reference
 */
contract ERC20RequestFeeProxyMaxMap is AccessControl {
    bytes32 public constant FEE_ADMIN_ROLE = keccak256("FEE_ADMIN_ROLE");
    // Event to declare a transfer with a reference
    event TransferWithReferenceAndFee(
        address tokenAddress,
        address to,
        uint256 amount,
        bytes indexed paymentReference,
        uint256 feeAmount,
        address feeAddress
    );

    // Fallback function returns funds to the sender
    receive() external payable {
        revert('not payable receive');
    }

    // Dynamic fee parameters
    uint256 public feeRateNumerator; // e.g.: 5 for 5%
    uint256 public feeRateDenominator; // e.g.: 100 for 5%
    address public addressRequestErc20ToBurn;

    // Mapping for token-specific Max fees
    mapping(address => uint256) public tokenRequestFeeMax;

    event UpdatedFeeRate(uint256 numerator, uint256 denominator);
    event UpdatedRequestErc20ToBurn(address newAddress);
    event UpdatedTokenRequestFeeMax(address indexed tokenAddress, uint256 max);

    constructor(
        address _addressRequestErc20ToBurn,
        uint256 _feeRateNumerator,
        uint256 _feeRateDenominator
    ) {
        require(_addressRequestErc20ToBurn != address(0), 'Burn address cannot be zero');
        addressRequestErc20ToBurn = _addressRequestErc20ToBurn;
        feeRateNumerator = _feeRateNumerator;
        feeRateDenominator = _feeRateDenominator;
        
        // Grant the contract deployer the default admin role: it will be able
        // to grant and revoke any roles
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(FEE_ADMIN_ROLE, msg.sender);
    }

    function setFeeRate(uint256 _numerator, uint256 _denominator) external onlyRole(FEE_ADMIN_ROLE) {
        require(_denominator != 0, 'Denominator cannot be zero');
        feeRateNumerator = _numerator;
        feeRateDenominator = _denominator;
        emit UpdatedFeeRate(_numerator, _denominator);
    }

    function setAddressRequestErc20ToBurn(address _newAddress) external onlyRole(FEE_ADMIN_ROLE) {
        require(_newAddress != address(0), 'Burn address cannot be zero');
        addressRequestErc20ToBurn = _newAddress;
        emit UpdatedRequestErc20ToBurn(_newAddress);
    }

    /**
     * @notice Sets the Max fee bounds for a specific token
     * @param _tokenAddress Address of the ERC20 token
     * @param _max Maximum fee amount for this token
     */
    function setTokenRequestFeeMax(
        address _tokenAddress,
        uint256 _max
    ) external onlyRole(FEE_ADMIN_ROLE) {
        tokenRequestFeeMax[_tokenAddress] = _max;
        emit UpdatedTokenRequestFeeMax(_tokenAddress, _max);
    }

    /**
    * @notice Performs a ERC20 token transfer with a reference
              and a transfer to a second address for the payment of a fee
    * @param _tokenAddress Address of the ERC20 token smart contract
    * @param _to Transfer recipient
    * @param _amount Amount to transfer
    * @param _paymentReference Reference of the payment related
    * @param _feeAmount The amount of the payment fee
    * @param _feeAddress The fee recipient
    */
    function transferFromWithReferenceAndFee(
        address _tokenAddress,
        address _to,
        uint256 _amount,
        bytes calldata _paymentReference,
        uint256 _feeAmount,
        address _feeAddress
    ) external {
        uint256 totalAmount = _amount + _feeAmount;
        uint256 requestFeeAmount = (totalAmount * feeRateNumerator) / feeRateDenominator;
        
        // Retrieve token-specific Max values
        uint256 tokenFeeMax = tokenRequestFeeMax[_tokenAddress];

        if (tokenFeeMax > 0 && requestFeeAmount > tokenFeeMax) {
            requestFeeAmount = tokenFeeMax;
        }
        // Fees are paid by the payer
        require(
            safeTransferFrom(_tokenAddress, addressRequestErc20ToBurn, requestFeeAmount),
            'transfer to burn failed'
        );

        require(safeTransferFrom(_tokenAddress, _to, _amount), 'payment transferFrom() failed');
        if (_feeAmount > 0 && _feeAddress != address(0)) {
            require(
                safeTransferFrom(_tokenAddress, _feeAddress, _feeAmount),
                'fee transferFrom() failed'
            );
        }

        emit TransferWithReferenceAndFee(
            _tokenAddress,
            _to,
            _amount,
            _paymentReference,
            _feeAmount,
            _feeAddress
        );
    }

    /**
     * @notice Call transferFrom ERC20 function and validates the return data of a ERC20 contract call.
     * @dev This is necessary because of non-standard ERC20 tokens that don't have a return value.
     * @return result The return value of the ERC20 call, returning true for non-standard tokens
     */
    function safeTransferFrom(
        address _tokenAddress,
        address _to,
        uint256 _amount
    ) internal returns (bool result) {
        /* solium-disable security/no-inline-assembly */
        // check if the address is a contract
        assembly {
            if iszero(extcodesize(_tokenAddress)) {
                revert(0, 0)
            }
        }

        // solium-disable-next-line security/no-low-level-calls
        (bool success, ) = _tokenAddress.call(
            abi.encodeWithSignature(
                'transferFrom(address,address,uint256)',
                msg.sender,
                _to,
                _amount
            )
        );

        assembly {
            switch returndatasize()
            case 0 {
                // not a standard erc20
                result := 1
            }
            case 32 {
                // standard erc20
                returndatacopy(0, 0, 32)
                result := mload(0)
            }
            default {
                // anything else, should revert for safety
                revert(0, 0)
            }
        }

        require(success, 'transferFrom() has been reverted');

        /* solium-enable security/no-inline-assembly */
        return result;
    }
}
