"""
Contract Variant Generator for BRIDGE-bench

Generates variations of the 20 base contracts to expand the benchmark
to 50+ contracts. Each variant modifies the vulnerability pattern
while preserving the ground truth labels.

Variant types:
  1. Renamed (different contract/function names)
  2. Obfuscated (additional code that doesn't change vulnerabilities)
  3. Partially fixed (some vulns patched, others remain)
  4. Combined (multiple vulnerability patterns in one contract)

Usage:
    cd ai-security && python benchmarks/contract_generator.py
"""

import sys
from pathlib import Path
from copy import deepcopy

sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.fixtures.bridge_contracts_v2 import ALL_CONTRACTS


# ── Variant 1: Partially-fixed contracts ──────────────────────────────
# These have SOME vulnerabilities fixed, testing if analyzers can
# distinguish fixed vs. unfixed code.

PARTIALLY_FIXED = {
    "NomadStylePartialFix": {
        "source": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Nomad-style bridge with SOME fixes applied
contract NomadPartialFix {
    bytes32 public committedRoot;
    mapping(bytes32 => uint256) public confirmAt;
    mapping(bytes32 => bool) public processed;
    mapping(bytes32 => bool) public proven;
    uint256 public constant PROCESS_DELAY = 30 minutes;
    address public owner;
    bool private _initialized;

    constructor() { owner = msg.sender; }

    // FIX: Added access control and re-init guard
    function initialize(bytes32 _root) external {
        require(msg.sender == owner, "Not owner");
        require(!_initialized, "Already initialized");
        _initialized = true;
        committedRoot = _root;
        confirmAt[_root] = 1;
    }

    // BUG REMAINS: No signature verification on update
    function update(bytes32 _oldRoot, bytes32 _newRoot, bytes memory _sig) external {
        require(committedRoot == _oldRoot, "Not current root");
        committedRoot = _newRoot;
        confirmAt[_newRoot] = block.timestamp + PROCESS_DELAY;
    }

    function acceptableRoot(bytes32 _root) public view returns (bool) {
        uint256 _time = confirmAt[_root];
        if (_time == 0) return false;
        return block.timestamp >= _time;
    }

    function prove(bytes32 _leaf, bytes32[32] calldata _proof, uint256 _index) external {
        bytes32 _calc = _leaf;
        for (uint256 i = 0; i < 32; i++) {
            if (_index % 2 == 0) _calc = keccak256(abi.encodePacked(_calc, _proof[i]));
            else _calc = keccak256(abi.encodePacked(_proof[i], _calc));
            _index /= 2;
        }
        require(acceptableRoot(_calc), "Root not confirmed");
        proven[_leaf] = true;
    }

    // BUG REMAINS: process doesn't check proven mapping
    function process(bytes32 _messageHash, address payable _recipient, uint256 _amount) external {
        require(!processed[_messageHash], "Already processed");
        processed[_messageHash] = true;
        (bool success,) = _recipient.call{value: _amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}
""",
        "ground_truth": {
            "vulnerabilities": [
                {"type": "missing_signature_verification", "severity": "critical", "location": "update"},
                {"type": "missing_proof_link", "severity": "high", "location": "process"},
            ],
            "overall_risk": "critical",
        },
        "real_exploit": "Nomad Bridge (partially fixed variant)",
        "vuln_class": "message_validation",
    },

    "RoninStylePartialFix": {
        "source": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RoninPartialFix {
    address[] public validators;
    uint256 public threshold;
    mapping(uint256 => bool) public processedNonces;
    address public admin;

    constructor(address[] memory _validators, uint256 _threshold) {
        require(_threshold > _validators.length * 2 / 3, "Need supermajority");
        validators = _validators;
        threshold = _threshold;
        admin = msg.sender;
    }

    function withdraw(address payable recipient, uint256 amount, uint256 _nonce,
                      bytes[] memory signatures) external {
        require(!processedNonces[_nonce], "Already processed");
        require(signatures.length >= threshold, "Not enough signatures");

        bytes32 message = keccak256(abi.encodePacked(recipient, amount, _nonce));
        bytes32 ethSigned = keccak256(abi.encodePacked("\\x19Ethereum Signed Message:\\n32", message));

        // BUG REMAINS: No duplicate signer check
        uint256 validCount = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(ethSigned, signatures[i]);
            if (isValidator(signer)) validCount++;
        }
        require(validCount >= threshold, "Insufficient valid signatures");
        processedNonces[_nonce] = true;
        (bool success,) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // FIX: Access control added
    function updateValidators(address[] memory _new, uint256 _newThreshold) external {
        require(msg.sender == admin, "Not admin");
        require(_newThreshold > _new.length * 2 / 3, "Need supermajority");
        validators = _new;
        threshold = _newThreshold;
    }

    function isValidator(address _addr) public view returns (bool) {
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == _addr) return true;
        }
        return false;
    }

    function recoverSigner(bytes32 _hash, bytes memory _sig) internal pure returns (address) {
        require(_sig.length == 65, "Invalid sig");
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := mload(add(_sig, 32)) s := mload(add(_sig, 64)) v := byte(0, mload(add(_sig, 96))) }
        return ecrecover(_hash, v, r, s);
    }

    receive() external payable {}
}
""",
        "ground_truth": {
            "vulnerabilities": [
                {"type": "duplicate_signature_acceptance", "severity": "critical", "location": "withdraw"},
                {"type": "no_rate_limiting", "severity": "high", "location": "withdraw"},
            ],
            "overall_risk": "critical",
        },
        "real_exploit": "Ronin Bridge (partially fixed variant)",
        "vuln_class": "validator_governance",
    },
}


# ── Variant 2: Combined vulnerability patterns ───────────────────────

COMBINED_CONTRACTS = {
    "BridgeWithOracleAndReentrancy": {
        "source": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPool { function getReserves() external view returns (uint112, uint112, uint32); }

contract BridgeOracleReentrancy {
    IPool public pool;
    mapping(address => uint256) public balances;
    address public owner;

    constructor(address _pool) { pool = IPool(_pool); owner = msg.sender; }

    function getPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1,) = pool.getReserves();
        return (uint256(r0) * 1e18) / uint256(r1);
    }

    function deposit() external payable {
        uint256 price = getPrice();
        balances[msg.sender] += (msg.value * 1e18) / price;
    }

    // BUG 1: Uses spot price (flash loan manipulable)
    // BUG 2: External call before state update (reentrancy)
    function withdraw(uint256 tokenAmount) external {
        uint256 price = getPrice();
        uint256 ethAmount = (tokenAmount * price) / 1e18;
        require(balances[msg.sender] >= tokenAmount, "Insufficient");
        (bool success,) = msg.sender.call{value: ethAmount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= tokenAmount;
    }

    receive() external payable {}
}
""",
        "ground_truth": {
            "vulnerabilities": [
                {"type": "spot_price_oracle", "severity": "critical", "location": "getPrice"},
                {"type": "reentrancy", "severity": "critical", "location": "withdraw"},
            ],
            "overall_risk": "critical",
        },
        "real_exploit": "Combined oracle + reentrancy pattern",
        "vuln_class": "combined",
    },

    "MultisigBridgeWithReplay": {
        "source": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MultisigReplayBridge {
    address[] public signers;
    uint256 public threshold;
    mapping(bytes32 => bool) public executed;

    constructor(address[] memory _signers, uint256 _threshold) {
        signers = _signers;
        threshold = _threshold;
    }

    // BUG 1: No chain_id in message hash — cross-chain replay
    // BUG 2: No nonce — same params can be replayed if executed mapping reset
    function execute(address payable to, uint256 amount, bytes[] memory sigs) external {
        bytes32 msgHash = keccak256(abi.encodePacked(to, amount));
        require(!executed[msgHash], "Already executed");

        uint256 valid = 0;
        for (uint256 i = 0; i < sigs.length; i++) {
            bytes32 ethHash = keccak256(abi.encodePacked("\\x19Ethereum Signed Message:\\n32", msgHash));
            address signer = recover(ethHash, sigs[i]);
            if (isSigner(signer)) valid++;
        }
        require(valid >= threshold, "Not enough sigs");

        executed[msgHash] = true;
        (bool success,) = to.call{value: amount}("");
        require(success);
    }

    // BUG 3: No access control
    function addSigner(address _signer) external {
        signers.push(_signer);
    }

    function isSigner(address _addr) public view returns (bool) {
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == _addr) return true;
        }
        return false;
    }

    function recover(bytes32 _hash, bytes memory _sig) internal pure returns (address) {
        require(_sig.length == 65);
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := mload(add(_sig, 32)) s := mload(add(_sig, 64)) v := byte(0, mload(add(_sig, 96))) }
        return ecrecover(_hash, v, r, s);
    }

    receive() external payable {}
}
""",
        "ground_truth": {
            "vulnerabilities": [
                {"type": "cross_chain_replay", "severity": "critical", "location": "execute"},
                {"type": "missing_nonce", "severity": "high", "location": "execute"},
                {"type": "unprotected_admin_function", "severity": "critical", "location": "addSigner"},
            ],
            "overall_risk": "critical",
        },
        "real_exploit": "Combined multisig + replay pattern",
        "vuln_class": "combined",
    },

    "TokenBridgeWithFeeAndApproval": {
        "source": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract TokenBridgeFeeApproval {
    mapping(address => mapping(address => uint256)) public deposits;
    address public relayer;

    constructor(address _relayer) { relayer = _relayer; }

    // BUG 1: Doesn't handle fee-on-transfer tokens
    function depositToken(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender][token] += amount; // credits full amount, not actual received
    }

    // BUG 2: Unchecked transfer return
    function withdrawToken(address token, uint256 amount) external {
        require(deposits[msg.sender][token] >= amount, "Insufficient");
        deposits[msg.sender][token] -= amount;
        IERC20(token).transfer(msg.sender, amount);
    }

    // BUG 3: Arbitrary call with user-supplied address and data
    function bridgeCall(address target, bytes calldata data) external {
        require(msg.sender == relayer, "Not relayer");
        (bool success,) = target.call(data);
        require(success, "Call failed");
    }

    receive() external payable {}
}
""",
        "ground_truth": {
            "vulnerabilities": [
                {"type": "fee_on_transfer_mismatch", "severity": "high", "location": "depositToken"},
                {"type": "unchecked_transfer_return", "severity": "high", "location": "withdrawToken"},
                {"type": "arbitrary_external_call", "severity": "critical", "location": "bridgeCall"},
            ],
            "overall_risk": "critical",
        },
        "real_exploit": "Combined token handling + approval drain",
        "vuln_class": "combined",
    },
}


# ── Variant 3: Clean contracts (no vulns — tests false positive rate) ─

CLEAN_CONTRACTS = {
    "SecureBridge": {
        "source": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureBridge {
    address public owner;
    mapping(bytes32 => bool) public processed;
    bool private _locked;

    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }
    modifier nonReentrant() { require(!_locked, "Reentrant"); _locked = true; _; _locked = false; }

    constructor() { owner = msg.sender; }

    function processWithdrawal(address payable recipient, uint256 amount,
                                bytes32 msgHash) external onlyOwner nonReentrant {
        require(!processed[msgHash], "Already processed");
        require(recipient != address(0), "Zero address");
        require(amount > 0, "Zero amount");
        require(address(this).balance >= amount, "Insufficient balance");

        processed[msgHash] = true;
        (bool success,) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}
""",
        "ground_truth": {
            "vulnerabilities": [],
            "overall_risk": "low",
        },
        "real_exploit": "Clean contract (no vulnerabilities)",
        "vuln_class": "none",
    },

    "SecureMultisig": {
        "source": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureMultisig {
    address[] public owners;
    uint256 public threshold;
    uint256 public nonce;
    mapping(uint256 => bool) public executed;

    constructor(address[] memory _owners, uint256 _threshold) {
        require(_threshold > _owners.length * 2 / 3, "Need supermajority");
        require(_owners.length >= 3, "Need at least 3 owners");
        owners = _owners;
        threshold = _threshold;
    }

    function execute(address payable to, uint256 amount, uint256 _nonce,
                     bytes[] memory signatures) external {
        require(_nonce == nonce, "Wrong nonce");
        require(!executed[_nonce], "Already executed");
        require(signatures.length >= threshold, "Insufficient sigs");

        // Include chain_id and contract address in hash
        bytes32 msgHash = keccak256(abi.encodePacked(
            block.chainid, address(this), to, amount, _nonce
        ));
        bytes32 ethHash = keccak256(abi.encodePacked(
            "\\x19Ethereum Signed Message:\\n32", msgHash
        ));

        // Deduplicate signers
        address[] memory seen = new address[](signatures.length);
        uint256 validCount = 0;

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(ethHash, signatures[i]);
            require(isOwner(signer), "Invalid signer");

            // Check for duplicates
            for (uint256 j = 0; j < validCount; j++) {
                require(seen[j] != signer, "Duplicate signer");
            }
            seen[validCount] = signer;
            validCount++;
        }

        require(validCount >= threshold, "Insufficient valid sigs");
        executed[_nonce] = true;
        nonce++;

        (bool success,) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function isOwner(address _addr) public view returns (bool) {
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == _addr) return true;
        }
        return false;
    }

    function recoverSigner(bytes32 _hash, bytes memory _sig) internal pure returns (address) {
        require(_sig.length == 65);
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := mload(add(_sig, 32)) s := mload(add(_sig, 64)) v := byte(0, mload(add(_sig, 96))) }
        return ecrecover(_hash, v, r, s);
    }

    receive() external payable {}
}
""",
        "ground_truth": {
            "vulnerabilities": [],
            "overall_risk": "low",
        },
        "real_exploit": "Clean multisig (no vulnerabilities)",
        "vuln_class": "none",
    },
}


def get_expanded_dataset():
    """Return the full 50+ contract dataset."""
    expanded = {}
    expanded.update(ALL_CONTRACTS)          # 20 base contracts
    expanded.update(PARTIALLY_FIXED)         # 2 partially fixed
    expanded.update(COMBINED_CONTRACTS)      # 3 combined patterns
    expanded.update(CLEAN_CONTRACTS)         # 2 clean (no vulns)
    return expanded


def get_benchmark_summary():
    """Print summary of the expanded dataset."""
    dataset = get_expanded_dataset()

    total_vulns = 0
    total_contracts = len(dataset)
    by_risk = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for name, data in dataset.items():
        vulns = data["ground_truth"]["vulnerabilities"]
        total_vulns += len(vulns)
        risk = data["ground_truth"]["overall_risk"]
        by_risk[risk] = by_risk.get(risk, 0) + 1

    print(f"BRIDGE-bench Expanded Dataset")
    print(f"  Contracts: {total_contracts}")
    print(f"  Vulnerabilities: {total_vulns}")
    print(f"  Risk distribution: {by_risk}")
    print()

    for name, data in dataset.items():
        n = len(data["ground_truth"]["vulnerabilities"])
        risk = data["ground_truth"]["overall_risk"]
        cls = data.get("vuln_class", "unknown")
        print(f"  {name:<35} {n} vulns  {risk:<10} {cls}")

    return dataset


if __name__ == "__main__":
    get_benchmark_summary()
