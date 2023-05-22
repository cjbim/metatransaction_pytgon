pragma solidity ^0.8.4;

import "./@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./@openzeppelin/contracts/utils/Counters.sol";
import "./@openzeppelin/contracts/access/Ownable.sol";
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);
}


contract TokenSender is ReentrancyGuard,Ownable{
    using Counters for Counters.Counter;
    mapping(address => Counters.Counter) private _nonces;
    event metatran(address indexed sender, address[] recipients, uint256[] amounts, address indexed token_contract_add );
    using ECDSA for bytes32;

    // Mapping for preventing Signature Replay
    mapping(bytes32 => bool) executed;
    mapping(address => bool) public whitelist; // 토큰 어드레스별로 whitelist 상태를 관리합니다.
    uint256 public whitelistCount; // whitelist에 포함된 주소의 개수를 추적합니다.

    // ...

    function addToWhitelist_struct(address[] memory addresses) public onlyOwner {
        for (uint256 i = 0; i < addresses.length; i++) {
            if (!whitelist[addresses[i]]) {
                whitelist[addresses[i]] = true;
                whitelistCount++;
            }
        }
    }
    function addToWhitelist(address addr) public onlyOwner {
    require(!whitelist[addr], "Address is already whitelisted");
    whitelist[addr] = true;
    whitelistCount++;
    }

    function removeFromWhitelist(address addr) public onlyOwner {
        if (whitelist[addr]) {
            delete whitelist[addr];
            whitelistCount--;
        }
    }


    function checkAddressInWhitelist(address addr) public view returns (bool) {
        return whitelist[addr];
    }
    
    // The message hash is converted to a Ethereum Signed Message Hash according to the EIP-191
    // Calling this function converts the messageHash into this format "\x19Ethereum Signed Message:\n" + len(message) + message)
    function transfer(address sender, uint256[] memory amounts, address[] memory recipients, address tokenContract, bytes memory signature) public {
        bytes32 messageHash = getHash(sender, amounts, recipients, tokenContract,_useNonce(sender));
        require(whitelist[tokenContract], "tokenContract is not whitelisted"); // 화이트리스트 체크
        bytes32 signedMessageHash = messageHash.toEthSignedMessageHash();

        // Require signature hasn't already been executed
        require(!executed[signedMessageHash], "Alredy executed");

        address signer = signedMessageHash.recover(signature);

        require(signer == sender, "Signature does not come from sender");

        // Signature executed
        executed[signedMessageHash] = true;
       for (uint256 i = 0; i < recipients.length; i++) {
            bool sent = IERC20(tokenContract).transferFrom(sender, recipients[i], amounts[i]);
            require(sent, "Transfer failed");
        }
        emit metatran(sender, recipients, amounts,tokenContract);
    }

    function getHash(address sender, uint256[] memory amounts, address[] memory recipients, address tokenContract, uint nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(sender, amounts, recipients, tokenContract, nonce));
    }

    function _useNonce(address owner) internal virtual returns (uint256 current) {
        Counters.Counter storage nonce = _nonces[owner];
        current = nonce.current();
        nonce.increment();
    }
    function nonces(address owner) public view virtual returns (uint256) {
        return _nonces[owner].current();
    }
}
