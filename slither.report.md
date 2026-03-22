INFO:Detectors:
Detector: arbitrary-send-erc20
L1BossBridge.depositTokensToL2(address,address,uint256) (src/L1BossBridge.sol#70-78) uses arbitrary from in transferFrom: token.safeTransferFrom(from,address(vault),amount) (src/L1BossBridge.sol#74)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#arbitrary-from-in-transferfrom
INFO:Detectors:
Detector: arbitrary-send-eth
L1BossBridge.sendToL1(uint8,bytes32,bytes32,bytes) (src/L1BossBridge.sol#112-125) sends eth to arbitrary user
        Dangerous calls:
        - (success,None) = target.call{value: value}(data) (src/L1BossBridge.sol#121)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#functions-that-send-ether-to-arbitrary-destinations
INFO:Detectors:
Detector: unused-return
L1Vault.approveTo(address,uint256) (src/L1Vault.sol#19-21) ignores return value by token.approve(target,amount) (src/L1Vault.sol#20)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#unused-return
INFO:Detectors:
Detector: missing-zero-check
L1BossBridge.sendToL1(uint8,bytes32,bytes32,bytes).target (src/L1BossBridge.sol#119) lacks a zero-check on :
                - (success,None) = target.call{value: value}(data) (src/L1BossBridge.sol#121)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation
INFO:Detectors:
Detector: reentrancy-events
Reentrancy in L1BossBridge.depositTokensToL2(address,address,uint256) (src/L1BossBridge.sol#70-78):
        External calls:
        - token.safeTransferFrom(from,address(vault),amount) (src/L1BossBridge.sol#74)
        Event emitted after the call(s):
        - Deposit(from,l2Recipient,amount) (src/L1BossBridge.sol#77)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-4
INFO:Detectors:
Detector: assembly
TokenFactory.deployToken(string,bytes) (src/TokenFactory.sol#23-29) uses assembly
        - INLINE ASM (src/TokenFactory.sol#24-26)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#assembly-usage
INFO:Detectors:
Detector: pragma
2 different versions of Solidity are used:
        - Version constraint ^0.8.20 is used by:
                -^0.8.20 (lib/openzeppelin-contracts/contracts/access/Ownable.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/interfaces/IERC20.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/interfaces/draft-IERC6093.sol#3)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/utils/Address.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/utils/Context.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/utils/Pausable.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/utils/Strings.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/utils/math/Math.sol#4)
                -^0.8.20 (lib/openzeppelin-contracts/contracts/utils/math/SignedMath.sol#4)
        - Version constraint 0.8.20 is used by:
                -0.8.20 (src/L1BossBridge.sol#15)
                -0.8.20 (src/L1Token.sol#2)
                -0.8.20 (src/L1Vault.sol#2)
                -0.8.20 (src/TokenFactory.sol#2)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#different-pragma-directives-are-used
INFO:Detectors:
Detector: solc-version
Version constraint 0.8.20 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
        - VerbatimInvalidDeduplication
        - FullInlinerNonExpressionSplitArgumentEvaluationOrder
        - MissingSideEffectsOnSelectorAccess.
It is used by:
        - 0.8.20 (src/L1BossBridge.sol#15)
        - 0.8.20 (src/L1Token.sol#2)
        - 0.8.20 (src/L1Vault.sol#2)
        - 0.8.20 (src/TokenFactory.sol#2)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity
INFO:Detectors:
Detector: low-level-calls
Low level call in L1BossBridge.sendToL1(uint8,bytes32,bytes32,bytes) (src/L1BossBridge.sol#112-125):
        - (success,None) = target.call{value: value}(data) (src/L1BossBridge.sol#121)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#low-level-calls
INFO:Detectors:
Detector: unindexed-event-address
Event L1BossBridge.Deposit(address,address,uint256) (src/L1BossBridge.sol#40) has address parameters but no indexed parameters
Event TokenFactory.TokenDeployed(string,address) (src/TokenFactory.sol#14) has address parameters but no indexed parameters
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#unindexed-event-address-parameters
INFO:Detectors:
Detector: constable-states
L1BossBridge.DEPOSIT_LIMIT (src/L1BossBridge.sol#30) should be constant 
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#state-variables-that-could-be-declared-constant
INFO:Detectors:
Detector: immutable-states
L1Vault.token (src/L1Vault.sol#13) should be immutable 
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#state-variables-that-could-be-declared-immutable
INFO:Slither:. analyzed (22 contracts with 100 detectors), 13 result(s) found