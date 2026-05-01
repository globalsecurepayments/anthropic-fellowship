"""
BRIDGE-bench v2: Expanded Contract Dataset (20+ contracts)

Extends test_contracts.py with 16 additional bridge vulnerability patterns
covering the full taxonomy from BENCHMARK_SPEC.md:
  - Message validation, signature verification, validator governance
  - Approval exploitation, oracle manipulation, access control
  - Initialization, upgrade mechanism, replay attacks
  - Rate limiting, delegatecall, flash loan vectors

Each contract is a minimal reproduction of a real exploit pattern.
Total: 20 contracts, 50+ labeled vulnerabilities.
"""

# Import original 4 contracts
from benchmarks.fixtures.test_contracts import TEST_CONTRACTS as _ORIGINAL

# ─── Contract 5: LiFi-style arbitrary calldata ────────────────────

LIFI_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC20 {
    function transferFrom(address,address,uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}
contract LiFiStyleBridge {
    // BUG: Arbitrary external call with user-controlled calldata
    // allows draining tokens from users who approved this contract
    function swapAndBridge(
        address swapTarget,
        bytes calldata swapCalldata,
        address token,
        uint256 amount,
        uint256 destChainId
    ) external payable {
        // BUG: No validation of swapTarget — could be token contract
        // BUG: No validation of swapCalldata — could be transferFrom
        (bool success,) = swapTarget.call{value: msg.value}(swapCalldata);
        require(success, "Swap failed");
        // Bridge the tokens (simplified)
        uint256 balance = IERC20(token).balanceOf(address(this));
        emit Bridge(msg.sender, destChainId, token, balance);
    }
    event Bridge(address indexed user, uint256 destChain, address token, uint256 amount);
}
"""
LIFI_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "arbitrary_external_call", "severity": "critical",
         "location": "swapAndBridge", "description": "User-controlled calldata to arbitrary address"},
        {"type": "approval_drain", "severity": "critical",
         "location": "swapAndBridge", "description": "Attacker can craft calldata as transferFrom to drain approved tokens"},
    ],
    "overall_risk": "critical",
}

# ─── Contract 6: Qubit-style zero value deposit ───────────────────

QUBIT_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract QubitStyleBridge {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public credits;
    // BUG: deposit() doesn't validate msg.value > 0 for native ETH
    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        credits[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    // BUG: depositETH credits the deposit but doesn't check msg.value
    function depositETH(uint256 amount) external {
        // BUG: msg.value not checked — amount parameter is trusted
        credits[msg.sender] += amount;
        emit Deposit(msg.sender, amount);
    }
    function withdraw(uint256 amount) external {
        require(credits[msg.sender] >= amount, "Insufficient");
        credits[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
    event Deposit(address indexed, uint256);
}
"""
QUBIT_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "zero_value_deposit", "severity": "critical",
         "location": "depositETH", "description": "Credits user without requiring msg.value"},
        {"type": "input_validation_missing", "severity": "critical",
         "location": "depositETH", "description": "amount parameter not validated against msg.value"},
    ],
    "overall_risk": "critical",
}

# ─── Contract 7: Harmony-style low multisig ───────────────────────

HARMONY_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract HarmonyStyleBridge {
    address[] public validators;
    uint256 public threshold; // BUG: 2 of 5 is too low
    mapping(bytes32 => bool) public executed;
    constructor(address[] memory _vals) {
        validators = _vals;
        threshold = 2; // BUG: Only 2 of N required
    }
    function execute(bytes32 txHash, bytes[] memory sigs) external {
        require(!executed[txHash], "Already executed");
        require(sigs.length >= threshold, "Not enough sigs");
        uint256 valid = 0;
        for (uint i = 0; i < sigs.length; i++) {
            address signer = recover(txHash, sigs[i]);
            if (isValidator(signer)) valid++;
        }
        require(valid >= threshold, "Invalid sigs");
        executed[txHash] = true;
        // Execute transaction...
    }
    // BUG: No timelock on validator changes
    function setValidators(address[] memory _new, uint256 _threshold) external {
        // BUG: No access control
        validators = _new;
        threshold = _threshold;
    }
    function isValidator(address a) public view returns (bool) {
        for (uint i = 0; i < validators.length; i++)
            if (validators[i] == a) return true;
        return false;
    }
    function recover(bytes32 h, bytes memory sig) internal pure returns (address) {
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := mload(add(sig,32)) s := mload(add(sig,64)) v := byte(0,mload(add(sig,96))) }
        return ecrecover(h, v, r, s);
    }
}
"""
HARMONY_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "low_validator_threshold", "severity": "critical",
         "location": "constructor", "description": "Only 2-of-N threshold"},
        {"type": "unprotected_admin_function", "severity": "critical",
         "location": "setValidators", "description": "Anyone can replace validators"},
        {"type": "no_timelock", "severity": "high",
         "location": "setValidators", "description": "No delay on validator changes"},
    ],
    "overall_risk": "critical",
}

# ─── Contract 8: PolyNetwork-style arbitrary call ─────────────────

POLYNETWORK_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract PolyNetworkStyleManager {
    address public keeper;
    mapping(bytes32 => bool) public processed;
    constructor(address _keeper) { keeper = _keeper; }
    // BUG: Executes arbitrary calls based on cross-chain message
    // No restriction on which contracts can be called
    function executeCrossChainTx(
        address toContract,
        bytes calldata method,
        bytes calldata args,
        bytes32 msgHash
    ) external {
        require(!processed[msgHash], "Processed");
        processed[msgHash] = true;
        // BUG: toContract is not restricted — attacker can call
        // the keeper storage contract to overwrite the keeper
        (bool success,) = toContract.call(abi.encodePacked(method, args));
        require(success, "Execution failed");
    }
    // BUG: keeper can be changed by anyone who controls executeCrossChainTx
    function changeKeeper(address newKeeper) external {
        require(msg.sender == address(this), "Only self");
        keeper = newKeeper;
    }
}
"""
POLYNETWORK_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "unrestricted_cross_chain_call", "severity": "critical",
         "location": "executeCrossChainTx", "description": "No whitelist on target contract"},
        {"type": "arbitrary_execution", "severity": "critical",
         "location": "executeCrossChainTx", "description": "Arbitrary calldata to arbitrary address"},
        {"type": "keeper_overwrite", "severity": "critical",
         "location": "changeKeeper", "description": "Can be called via executeCrossChainTx to self"},
    ],
    "overall_risk": "critical",
}

# ─── Contract 9: Bad proxy bridge ─────────────────────────────────

BAD_PROXY_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BadProxyBridge {
    address public implementation;
    address public admin;
    mapping(address => uint256) public balances;
    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }
    // BUG: No access control on upgrade
    function upgradeTo(address newImpl) external {
        implementation = newImpl;
    }
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
    receive() external payable { balances[msg.sender] += msg.value; }
}
"""
BAD_PROXY_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "unprotected_upgrade", "severity": "critical",
         "location": "upgradeTo", "description": "Anyone can change implementation"},
        {"type": "delegatecall_to_untrusted", "severity": "critical",
         "location": "fallback", "description": "delegatecall to mutable implementation"},
    ],
    "overall_risk": "critical",
}

# ─── Contract 10: Replay attack bridge ────────────────────────────

REPLAY_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ReplayBridge {
    address public relayer;
    mapping(bytes32 => bool) public processed;
    constructor(address _relayer) { relayer = _relayer; }
    function processMessage(
        address recipient, uint256 amount, uint256 nonce, bytes memory sig
    ) external {
        // BUG: Message hash doesn't include chain ID
        // Same message valid on multiple chains
        bytes32 msgHash = keccak256(abi.encodePacked(recipient, amount, nonce));
        require(!processed[msgHash], "Processed");
        // BUG: No check that sig is from relayer
        processed[msgHash] = true;
        (bool ok,) = recipient.call{value: amount}("");
        require(ok);
    }
    receive() external payable {}
}
"""
REPLAY_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "cross_chain_replay", "severity": "critical",
         "location": "processMessage", "description": "No chain ID in message hash"},
        {"type": "missing_signature_verification", "severity": "critical",
         "location": "processMessage", "description": "Signature not verified against relayer"},
    ],
    "overall_risk": "critical",
}

# ─── Contract 11: Delegatecall bridge ─────────────────────────────

DELEGATECALL_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract DelegateCallBridge {
    address public owner;
    mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; }
    function deposit() external payable { balances[msg.sender] += msg.value; }
    // BUG: delegatecall to user-supplied address
    function execute(address target, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        // BUG: delegatecall runs in this contract's context
        // target can modify storage (owner, balances)
        (bool ok,) = target.delegatecall(data);
        require(ok);
    }
}
"""
DELEGATECALL_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "delegatecall_to_user_input", "severity": "critical",
         "location": "execute", "description": "delegatecall to user-controlled address can overwrite storage"},
    ],
    "overall_risk": "critical",
}

# ─── Contract 12: Timelock bypass ─────────────────────────────────

TIMELOCK_BYPASS_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract TimelockBypassBridge {
    address public owner;
    uint256 public withdrawalDelay = 1 days;
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => uint256) public withdrawalTimestamps;
    constructor() { owner = msg.sender; }
    function requestWithdrawal(uint256 amount) external {
        pendingWithdrawals[msg.sender] = amount;
        withdrawalTimestamps[msg.sender] = block.timestamp + withdrawalDelay;
    }
    function executeWithdrawal() external {
        require(block.timestamp >= withdrawalTimestamps[msg.sender], "Too early");
        uint256 amount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
    // BUG: Emergency function bypasses timelock entirely
    function emergencyWithdraw(address to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        // No timelock check — owner can drain immediately
        (bool ok,) = to.call{value: amount}("");
        require(ok);
    }
    receive() external payable {}
}
"""
TIMELOCK_BYPASS_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "timelock_bypass", "severity": "high",
         "location": "emergencyWithdraw", "description": "Owner can bypass timelock via emergency function"},
        {"type": "centralization_risk", "severity": "medium",
         "location": "emergencyWithdraw", "description": "Single owner can drain all funds"},
    ],
    "overall_risk": "high",
}

# ─── Contract 13: Signature malleability ──────────────────────────

MALLEABLE_SIG_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MalleableSigBridge {
    address public signer;
    mapping(bytes32 => bool) public usedSigs;
    constructor(address _signer) { signer = _signer; }
    function withdraw(address to, uint256 amount, bytes memory sig) external {
        bytes32 msgHash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethHash = keccak256(abi.encodePacked("\\x19Ethereum Signed Message:\\n32", msgHash));
        // BUG: Uses raw signature bytes as unique ID
        // Malleable signatures (flipping s) produce different bytes but same signer
        bytes32 sigHash = keccak256(sig);
        require(!usedSigs[sigHash], "Used");
        usedSigs[sigHash] = true;
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := mload(add(sig,32)) s := mload(add(sig,64)) v := byte(0,mload(add(sig,96))) }
        // BUG: No check that s is in lower half of secp256k1 order
        require(ecrecover(ethHash, v, r, s) == signer, "Invalid sig");
        (bool ok,) = to.call{value: amount}("");
        require(ok);
    }
    receive() external payable {}
}
"""
MALLEABLE_SIG_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "signature_malleability", "severity": "high",
         "location": "withdraw", "description": "Replay via malleable s-value in ECDSA"},
        {"type": "replay_via_sig_hash", "severity": "high",
         "location": "withdraw", "description": "Using sig bytes as nonce allows replay with flipped sig"},
    ],
    "overall_risk": "high",
}

# ─── Contract 14: Unchecked ERC20 transfer ────────────────────────

UNCHECKED_TRANSFER_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
contract UncheckedTransferBridge {
    mapping(address => mapping(address => uint256)) public deposits;
    function deposit(address token, uint256 amount) external {
        // BUG: Return value of transferFrom not checked
        // Some tokens (USDT) don't return bool
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender][token] += amount;
    }
    function withdraw(address token, uint256 amount) external {
        require(deposits[msg.sender][token] >= amount, "Insufficient");
        deposits[msg.sender][token] -= amount;
        // BUG: Return value of transfer not checked
        IERC20(token).transfer(msg.sender, amount);
    }
}
"""
UNCHECKED_TRANSFER_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "unchecked_transfer_return", "severity": "high",
         "location": "deposit", "description": "transferFrom return value not checked"},
        {"type": "unchecked_transfer_return", "severity": "high",
         "location": "withdraw", "description": "transfer return value not checked"},
    ],
    "overall_risk": "high",
}

# ─── Contract 15: Double-spend reentrancy ─────────────────────────

DOUBLE_SPEND_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract DoubleSpendBridge {
    mapping(bytes32 => bool) public processed;
    mapping(address => uint256) public balances;
    function processWithdrawal(bytes32 msgHash, address to, uint256 amount) external {
        require(!processed[msgHash], "Processed");
        // BUG: External call BEFORE marking as processed
        (bool ok,) = to.call{value: amount}("");
        require(ok);
        // State update after external call — reentrancy!
        processed[msgHash] = true;
    }
    function deposit() external payable { balances[msg.sender] += msg.value; }
}
"""
DOUBLE_SPEND_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "reentrancy", "severity": "critical",
         "location": "processWithdrawal", "description": "External call before state update"},
        {"type": "double_spend", "severity": "critical",
         "location": "processWithdrawal", "description": "Same msgHash can be used multiple times via reentrancy"},
    ],
    "overall_risk": "critical",
}

# ─── Contract 16: Gas bomb / DoS ─────────────────────────────────

GAS_BOMB_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract GasBombBridge {
    address[] public validators;
    uint256 public threshold;
    constructor(address[] memory _vals, uint256 _t) {
        validators = _vals;
        threshold = _t;
    }
    function addValidator(address v) external {
        // BUG: No limit on validator array size
        validators.push(v);
    }
    function isValidator(address v) public view returns (bool) {
        // BUG: Unbounded loop — if validators array is huge, this exceeds gas limit
        for (uint i = 0; i < validators.length; i++) {
            if (validators[i] == v) return true;
        }
        return false;
    }
    function withdraw(address to, uint256 amount, bytes[] memory sigs) external {
        require(sigs.length >= threshold, "Not enough");
        uint256 valid = 0;
        for (uint i = 0; i < sigs.length; i++) {
            // Each isValidator call iterates the full array — O(n*m)
            if (isValidator(address(uint160(uint256(keccak256(sigs[i])))))) valid++;
        }
        require(valid >= threshold);
        (bool ok,) = to.call{value: amount}("");
        require(ok);
    }
    receive() external payable {}
}
"""
GAS_BOMB_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "unbounded_loop_dos", "severity": "high",
         "location": "isValidator", "description": "Unbounded array iteration can exceed gas limit"},
        {"type": "unprotected_push", "severity": "medium",
         "location": "addValidator", "description": "No access control on adding validators"},
    ],
    "overall_risk": "high",
}

# ─── Contract 17: Selfdestruct accounting ─────────────────────────

SELFDESTRUCT_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SelfDestructBridge {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
    // BUG: Contract assumes address(this).balance == totalDeposits
    // but selfdestruct can force-send ETH, breaking this invariant
    function isFullyBacked() public view returns (bool) {
        return address(this).balance >= totalDeposits;
    }
}
"""
SELFDESTRUCT_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "forced_eth_reception", "severity": "medium",
         "location": "isFullyBacked", "description": "selfdestruct can force ETH, breaking balance invariant"},
    ],
    "overall_risk": "medium",
}

# ─── Contract 18: Front-running relayer ───────────────────────────

FRONTRUN_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract FrontRunBridge {
    mapping(bytes32 => bool) public processed;
    event WithdrawalRequest(address indexed to, uint256 amount, bytes32 hash);
    // BUG: Withdrawal details are visible in mempool
    // Relayer/miner can front-run with different recipient
    function requestWithdrawal(address to, uint256 amount, bytes32 proof) external {
        bytes32 h = keccak256(abi.encodePacked(to, amount, proof));
        require(!processed[h], "Processed");
        processed[h] = true;
        // BUG: No commit-reveal scheme — tx details visible before inclusion
        (bool ok,) = to.call{value: amount}("");
        require(ok);
        emit WithdrawalRequest(to, amount, h);
    }
    receive() external payable {}
}
"""
FRONTRUN_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "front_running", "severity": "medium",
         "location": "requestWithdrawal", "description": "No commit-reveal; details visible in mempool"},
    ],
    "overall_risk": "medium",
}

# ─── Contract 19: Missing event emission ──────────────────────────

MISSING_EVENTS_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MissingEventsBridge {
    address public owner;
    address public relayer;
    uint256 public fee;
    constructor() { owner = msg.sender; }
    function setRelayer(address _r) external {
        require(msg.sender == owner);
        // BUG: No event emitted — off-chain monitoring can't detect change
        relayer = _r;
    }
    function setFee(uint256 _f) external {
        require(msg.sender == owner);
        // BUG: No event, no upper bound on fee
        fee = _f;
    }
    function bridge(uint256 amount) external payable {
        require(msg.value >= amount + fee, "Insufficient");
        // BUG: Fee can be set to drain user funds
        (bool ok,) = owner.call{value: fee}("");
        require(ok);
    }
    receive() external payable {}
}
"""
MISSING_EVENTS_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "missing_event_emission", "severity": "low",
         "location": "setRelayer", "description": "Critical state change without event"},
        {"type": "unbounded_fee", "severity": "medium",
         "location": "setFee", "description": "No upper bound on fee parameter"},
    ],
    "overall_risk": "medium",
}

# ─── Contract 20: Token bridge with fee-on-transfer ───────────────

FEE_ON_TRANSFER_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC20 {
    function transferFrom(address,address,uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}
contract FeeOnTransferBridge {
    mapping(address => mapping(address => uint256)) public deposits;
    function deposit(address token, uint256 amount) external {
        // BUG: Assumes amount received == amount parameter
        // Fee-on-transfer tokens will deliver less than amount
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender][token] += amount; // Credits full amount
    }
    function withdraw(address token, uint256 amount) external {
        require(deposits[msg.sender][token] >= amount);
        deposits[msg.sender][token] -= amount;
        IERC20(token).transferFrom(address(this), msg.sender, amount);
    }
}
"""
FEE_ON_TRANSFER_GROUND_TRUTH = {
    "vulnerabilities": [
        {"type": "fee_on_transfer_mismatch", "severity": "high",
         "location": "deposit", "description": "Credits full amount but may receive less with fee-on-transfer tokens"},
    ],
    "overall_risk": "high",
}

# ─── Combined Registry ────────────────────────────────────────────

# Start with original 4 contracts
ALL_CONTRACTS = dict(_ORIGINAL)

# Add 16 new contracts
ALL_CONTRACTS.update({
    "LiFiStyle": {
        "source": LIFI_PATTERN,
        "ground_truth": LIFI_GROUND_TRUTH,
        "real_exploit": "LiFi Protocol, Mar 2022 + Jul 2024, $10.6M",
        "vuln_class": "approval_exploitation",
    },
    "QubitStyle": {
        "source": QUBIT_PATTERN,
        "ground_truth": QUBIT_GROUND_TRUTH,
        "real_exploit": "Qubit Finance, Jan 2022, $80M",
        "vuln_class": "input_validation",
    },
    "HarmonyStyle": {
        "source": HARMONY_PATTERN,
        "ground_truth": HARMONY_GROUND_TRUTH,
        "real_exploit": "Harmony Horizon, Jun 2022, $100M",
        "vuln_class": "validator_governance",
    },
    "PolyNetworkStyle": {
        "source": POLYNETWORK_PATTERN,
        "ground_truth": POLYNETWORK_GROUND_TRUTH,
        "real_exploit": "Poly Network, Aug 2021, $610M",
        "vuln_class": "message_validation",
    },
    "BadProxyBridge": {
        "source": BAD_PROXY_PATTERN,
        "ground_truth": BAD_PROXY_GROUND_TRUTH,
        "real_exploit": "Various proxy upgrade exploits",
        "vuln_class": "upgrade_mechanism",
    },
    "ReplayBridge": {
        "source": REPLAY_PATTERN,
        "ground_truth": REPLAY_GROUND_TRUTH,
        "real_exploit": "Cross-chain replay attacks (Optimism, etc.)",
        "vuln_class": "message_validation",
    },
    "DelegateCallBridge": {
        "source": DELEGATECALL_PATTERN,
        "ground_truth": DELEGATECALL_GROUND_TRUTH,
        "real_exploit": "Parity Multisig, Nov 2017, $150M",
        "vuln_class": "access_control",
    },
    "TimelockBypass": {
        "source": TIMELOCK_BYPASS_PATTERN,
        "ground_truth": TIMELOCK_BYPASS_GROUND_TRUTH,
        "real_exploit": "Common pattern in DeFi governance",
        "vuln_class": "access_control",
    },
    "MalleableSig": {
        "source": MALLEABLE_SIG_PATTERN,
        "ground_truth": MALLEABLE_SIG_GROUND_TRUTH,
        "real_exploit": "ECDSA malleability attacks",
        "vuln_class": "signature_verification",
    },
    "UncheckedTransfer": {
        "source": UNCHECKED_TRANSFER_PATTERN,
        "ground_truth": UNCHECKED_TRANSFER_GROUND_TRUTH,
        "real_exploit": "USDT/non-standard ERC20 issues",
        "vuln_class": "input_validation",
    },
    "DoubleSpend": {
        "source": DOUBLE_SPEND_PATTERN,
        "ground_truth": DOUBLE_SPEND_GROUND_TRUTH,
        "real_exploit": "Classic reentrancy pattern",
        "vuln_class": "reentrancy",
    },
    "GasBomb": {
        "source": GAS_BOMB_PATTERN,
        "ground_truth": GAS_BOMB_GROUND_TRUTH,
        "real_exploit": "DoS via unbounded loops",
        "vuln_class": "denial_of_service",
    },
    "SelfDestruct": {
        "source": SELFDESTRUCT_PATTERN,
        "ground_truth": SELFDESTRUCT_GROUND_TRUTH,
        "real_exploit": "Force-sending ETH attacks",
        "vuln_class": "accounting_error",
    },
    "FrontRun": {
        "source": FRONTRUN_PATTERN,
        "ground_truth": FRONTRUN_GROUND_TRUTH,
        "real_exploit": "MEV/front-running in bridges",
        "vuln_class": "front_running",
    },
    "MissingEvents": {
        "source": MISSING_EVENTS_PATTERN,
        "ground_truth": MISSING_EVENTS_GROUND_TRUTH,
        "real_exploit": "Monitoring blind spots",
        "vuln_class": "missing_events",
    },
    "FeeOnTransfer": {
        "source": FEE_ON_TRANSFER_PATTERN,
        "ground_truth": FEE_ON_TRANSFER_GROUND_TRUTH,
        "real_exploit": "Fee-on-transfer token issues",
        "vuln_class": "token_handling",
    },
})


# ─── Pattern 21: Drift-style Governance Takeover + Oracle Manipulation ─────
# Real exploit: Drift Protocol, Apr 2026, $285M — attacker social-engineered
# multisig signers into pre-signing nonce transactions, exploited 2/5 threshold
# with zero timelock, created fake token with wash-traded price, used as
# collateral at manipulated oracle prices, drained funds, bridged $232M USDC
# via Circle CCTP from Solana to Ethereum. Attributed to DPRK.

DRIFT_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

contract DriftStyleVault {
    address[] public councilMembers;
    uint256 public threshold;
    uint256 public timelockDelay;

    IPriceOracle public oracle;
    mapping(address => bool) public supportedCollateral;
    mapping(address => mapping(address => uint256)) public collateralBalances;
    mapping(address => uint256) public borrowedAmounts;

    address public admin;
    uint256 public totalDeposits;

    // BUG 1: Low threshold (2 of 5) — social engineering 2 signers is feasible
    // BUG 2: Zero timelock — no delay on governance actions
    constructor(address[] memory _council, address _oracle) {
        require(_council.length >= 2, "Need at least 2");
        councilMembers = _council;
        threshold = 2;           // BUG: Only 2/5 needed
        timelockDelay = 0;       // BUG: No timelock
        oracle = IPriceOracle(_oracle);
        admin = msg.sender;
    }

    // BUG 3: Anyone can add collateral tokens — no whitelist governance
    function addSupportedCollateral(address token) external {
        // BUG: No council approval required
        supportedCollateral[token] = true;
    }

    function depositCollateral(address token, uint256 amount) external {
        require(supportedCollateral[token], "Not supported");
        // Assume ERC20 transferFrom happens here
        collateralBalances[msg.sender][token] += amount;
    }

    // BUG 4: Uses spot oracle price — manipulable with fake token + wash trading
    function getCollateralValue(address user, address token) public view returns (uint256) {
        uint256 balance = collateralBalances[user][token];
        uint256 price = oracle.getPrice(token);  // BUG: trusts oracle blindly
        return balance * price / 1e18;
    }

    // BUG 5: No withdrawal rate limiting — 31 withdrawals in 12 minutes
    function borrow(address token, uint256 borrowAmount) external {
        uint256 collateralValue = getCollateralValue(msg.sender, token);
        require(collateralValue >= borrowAmount * 2, "Undercollateralized");
        borrowedAmounts[msg.sender] += borrowAmount;

        // Transfer borrowed funds
        (bool success,) = msg.sender.call{value: borrowAmount}("");
        require(success, "Transfer failed");
    }

    // BUG 6: Council migration with zero timelock — attacker can swap all members instantly
    function migrateCouncil(
        address[] memory newMembers,
        uint256 newThreshold,
        bytes[] memory signatures
    ) external {
        require(signatures.length >= threshold, "Insufficient sigs");
        // BUG: No timelock delay — changes take effect immediately
        // BUG: Pre-signed transactions via durable nonces can be replayed
        councilMembers = newMembers;
        threshold = newThreshold;
    }

    receive() external payable {
        totalDeposits += msg.value;
    }
}
"""

DRIFT_GROUND_TRUTH = {
    "vulnerabilities": [
        {
            "type": "low_multisig_threshold",
            "severity": "critical",
            "location": "constructor",
            "description": "2/5 Security Council threshold — attacker only needs to compromise 2 signers",
        },
        {
            "type": "zero_timelock",
            "severity": "critical",
            "location": "constructor/migrateCouncil",
            "description": "No timelock on governance actions — changes take effect immediately",
        },
        {
            "type": "oracle_manipulation_fake_token",
            "severity": "critical",
            "location": "getCollateralValue",
            "description": "Blindly trusts oracle price — attacker can create fake token with wash-traded price history",
        },
        {
            "type": "unprotected_admin_function",
            "severity": "critical",
            "location": "addSupportedCollateral",
            "description": "Anyone can add collateral tokens without council approval — enables fake token attack",
        },
        {
            "type": "no_rate_limiting",
            "severity": "high",
            "location": "borrow",
            "description": "No withdrawal rate limiting — attacker executed 31 withdrawals in 12 minutes",
        },
    ],
    "overall_risk": "critical",
}

ALL_CONTRACTS["DriftStyle"] = {
    "source": DRIFT_PATTERN,
    "ground_truth": DRIFT_GROUND_TRUTH,
    "real_exploit": "Drift Protocol $285M, Apr 2026 (DPRK/Lazarus)",
    "vuln_class": "governance_takeover",
}


# ─── Pattern 22: CCTP-style Bridge (Circle Cross-Chain Transfer Protocol) ──
# The Drift attacker bridged $232M in stolen USDC via Circle CCTP.
# Circle had ~6 hours to freeze but didn't. The contract-level issues:
# single attester, no rate limiting, no amount caps, no timelock on rotation.

CCTP_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20Burn {
    function burn(uint256 amount) external;
    function mint(address to, uint256 amount) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract CCTPStyleBridge {
    address public attester;
    address public controller;
    IERC20Burn public usdc;
    uint32 public localDomain;
    uint64 public nextNonce;
    mapping(bytes32 => bool) public usedNonces;
    mapping(uint32 => bool) public enabledDomains;
    bool public paused;

    constructor(address _usdc, address _attester, uint32 _domain) {
        usdc = IERC20Burn(_usdc);
        attester = _attester;
        controller = msg.sender;
        localDomain = _domain;
    }

    // BUG 1: No rate limiting — Drift attacker bridged $232M rapidly
    function depositForBurn(uint256 amount, uint32 destDomain, address recipient) external {
        require(!paused && amount > 0 && enabledDomains[destDomain]);
        usdc.transferFrom(msg.sender, address(this), amount);
        usdc.burn(amount);
        nextNonce++;
    }

    // BUG 2: Single attester — compromise means full control
    // BUG 3: No amount sanity check — could mint billions
    function receiveMessage(bytes calldata message, bytes calldata attestation) external {
        require(!paused);
        (uint32 srcDomain, uint32 destDomain, uint64 nonce, , address recipient, uint256 amount)
            = abi.decode(message, (uint32, uint32, uint64, address, address, uint256));
        require(destDomain == localDomain);
        bytes32 nonceKey = keccak256(abi.encodePacked(srcDomain, nonce));
        require(!usedNonces[nonceKey]);
        usedNonces[nonceKey] = true;

        bytes32 ethHash = keccak256(abi.encodePacked(
            "\\x19Ethereum Signed Message:\\n32", keccak256(message)
        ));
        require(_recover(ethHash, attestation) == attester, "Bad attestation");
        usdc.mint(recipient, amount);
    }

    // BUG 4: No timelock on attester rotation
    function rotateAttester(address newAttester) external {
        require(msg.sender == controller);
        attester = newAttester;
    }

    function enableDomain(uint32 domain) external {
        require(msg.sender == controller);
        enabledDomains[domain] = true;
    }

    function pause() external { require(msg.sender == controller); paused = true; }

    function _recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65);
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := mload(add(sig, 32)) s := mload(add(sig, 64)) v := byte(0, mload(add(sig, 96))) }
        return ecrecover(hash, v, r, s);
    }
}
"""

CCTP_GROUND_TRUTH = {
    "vulnerabilities": [
        {
            "type": "no_rate_limiting",
            "severity": "critical",
            "location": "depositForBurn",
            "description": "No per-transfer or aggregate volume limits — Drift attacker bridged $232M rapidly",
        },
        {
            "type": "centralization_risk",
            "severity": "critical",
            "location": "receiveMessage",
            "description": "Single attester signature — compromise gives full control over minting",
        },
        {
            "type": "no_amount_sanity_check",
            "severity": "high",
            "location": "receiveMessage",
            "description": "No maximum mint amount — valid attestation can mint arbitrary amounts",
        },
        {
            "type": "zero_timelock",
            "severity": "critical",
            "location": "rotateAttester",
            "description": "Attester rotation takes effect immediately with no timelock or multisig",
        },
    ],
    "overall_risk": "critical",
}

ALL_CONTRACTS["CCTPStyle"] = {
    "source": CCTP_PATTERN,
    "ground_truth": CCTP_GROUND_TRUTH,
    "real_exploit": "Circle CCTP — used in Drift $285M bridge, Apr 2026",
    "vuln_class": "bridge_centralization",
}


def get_stats():
    total_vulns = sum(
        len(d["ground_truth"]["vulnerabilities"]) for d in ALL_CONTRACTS.values()
    )
    by_class = {}
    for name, data in ALL_CONTRACTS.items():
        cls = data.get("vuln_class", "unknown")
        by_class.setdefault(cls, []).append(name)

    return {
        "total_contracts": len(ALL_CONTRACTS),
        "total_vulnerabilities": total_vulns,
        "by_class": by_class,
    }


if __name__ == "__main__":
    stats = get_stats()
    print(f"BRIDGE-bench v2: {stats['total_contracts']} contracts, "
          f"{stats['total_vulnerabilities']} labeled vulnerabilities")
    print()
    print("By vulnerability class:")
    for cls, contracts in sorted(stats["by_class"].items()):
        print(f"  {cls:<30} {len(contracts)} contracts: {', '.join(contracts)}")
    print()
    for name, data in ALL_CONTRACTS.items():
        n = len(data["ground_truth"]["vulnerabilities"])
        risk = data["ground_truth"]["overall_risk"]
        print(f"  {name:<22} {n} vulns  risk={risk:<10} {data.get('real_exploit', '')}")
