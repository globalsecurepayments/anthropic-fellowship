"""
Realistic Bridge Vulnerability Test Suite

Each contract is modeled after the vulnerability pattern from a real
bridge exploit, simplified to isolate the specific bug class while
remaining analyzable by both static tools and LLM agents.

These are NOT the actual exploited contracts — they're minimal
reproductions of the vulnerability patterns for benchmarking purposes.
"""

# ─── Pattern 1: Wormhole-style Signature Verification Bypass ───────
# Real exploit: Attacker bypassed guardian signature verification
# to mint 120k wETH ($320M). The verify_signatures function accepted
# a deprecated system program as the sysvar address.

WORMHOLE_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Simplified Wormhole-style bridge with signature verification flaw
contract WormholeStyleBridge {
    address public guardian;
    mapping(bytes32 => bool) public consumedVAAs;
    mapping(address => uint256) public wrappedBalances;
    
    constructor(address _guardian) {
        guardian = _guardian;
    }
    
    // BUG: The signature verification uses an external contract call
    // to verify the guardian set, but doesn't validate that the
    // verification contract is the legitimate one.
    // An attacker can pass their own "verifier" contract that always
    // returns true.
    function submitVAA(
        bytes memory vaa,
        address verificationContract
    ) external {
        // BUG: No validation that verificationContract is trusted
        (bool valid, ) = verificationContract.staticcall(
            abi.encodeWithSignature("verify(bytes)", vaa)
        );
        require(valid, "Invalid VAA");
        
        bytes32 vaaHash = keccak256(vaa);
        require(!consumedVAAs[vaaHash], "Already consumed");
        consumedVAAs[vaaHash] = true;
        
        // Decode and process the VAA
        (address recipient, uint256 amount) = abi.decode(vaa, (address, uint256));
        wrappedBalances[recipient] += amount;
    }
    
    function withdraw(uint256 amount) external {
        require(wrappedBalances[msg.sender] >= amount, "Insufficient balance");
        wrappedBalances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    receive() external payable {}
    
    event VAAProcessed(bytes32 indexed vaaHash, address recipient, uint256 amount);
}
"""

WORMHOLE_GROUND_TRUTH = {
    "vulnerabilities": [
        {
            "type": "untrusted_external_call",
            "severity": "critical",
            "location": "submitVAA",
            "description": "Verification contract address is user-supplied with no validation",
        },
        {
            "type": "reentrancy",
            "severity": "high", 
            "location": "withdraw",
            "description": "External call before state is fully settled in wrappedBalances context",
        },
    ],
    "overall_risk": "critical",
}

# ─── Pattern 2: Nomad-style Zero Root Initialization ───────────────
# Real exploit: A routine upgrade set the trusted Merkle root to 0x00.
# Since messages[0x00] mapped to 0 and confirmAt[0x00] mapped to 0,
# the zero hash was treated as "confirmed" (block.timestamp > 0).
# 1175+ copycat transactions drained $190M.

NOMAD_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NomadStyleReplica {
    bytes32 public committedRoot;
    mapping(bytes32 => uint256) public confirmAt;
    mapping(bytes32 => bool) public processed;
    
    uint256 public constant PROCESS_DELAY = 30 minutes;
    address public updater;
    
    // BUG 1: No access control — anyone can call initialize
    // BUG 2: Can be called multiple times (no initializer guard)
    // BUG 3: If _root is set to bytes32(0), then confirmAt[0x00] = 1,
    //         and since any uninitialized mapping entry is 0,
    //         prove() will accept the zero root for ANY message
    function initialize(bytes32 _root) external {
        committedRoot = _root;
        confirmAt[_root] = 1; // Immediately confirmed
    }
    
    function update(bytes32 _oldRoot, bytes32 _newRoot, bytes memory _sig) external {
        require(committedRoot == _oldRoot, "Not current root");
        // BUG: No signature verification on _sig
        // Anyone can propose a new root
        committedRoot = _newRoot;
        confirmAt[_newRoot] = block.timestamp + PROCESS_DELAY;
    }
    
    function acceptableRoot(bytes32 _root) public view returns (bool) {
        uint256 _time = confirmAt[_root];
        if (_time == 0) return false;
        return block.timestamp >= _time;
    }
    
    function prove(bytes32 _leaf, bytes32[32] calldata _proof, uint256 _index) external returns (bool) {
        bytes32 _calc = _leaf;
        for (uint256 i = 0; i < 32; i++) {
            if (_index % 2 == 0) {
                _calc = keccak256(abi.encodePacked(_calc, _proof[i]));
            } else {
                _calc = keccak256(abi.encodePacked(_proof[i], _calc));
            }
            _index /= 2;
        }
        require(acceptableRoot(_calc), "Root not confirmed");
        return true;
    }
    
    function process(
        bytes32 _messageHash,
        address payable _recipient,
        uint256 _amount
    ) external {
        require(!processed[_messageHash], "Already processed");
        processed[_messageHash] = true;
        
        (bool success, ) = _recipient.call{value: _amount}("");
        require(success, "Transfer failed");
    }
    
    receive() external payable {}
}
"""

NOMAD_GROUND_TRUTH = {
    "vulnerabilities": [
        {
            "type": "unprotected_initializer",
            "severity": "critical",
            "location": "initialize",
            "description": "No access control, can be called by anyone",
        },
        {
            "type": "reinitializable",
            "severity": "critical",
            "location": "initialize",
            "description": "No guard against multiple calls",
        },
        {
            "type": "zero_root_acceptance",
            "severity": "critical",
            "location": "initialize/acceptableRoot",
            "description": "Setting root to 0x00 makes all messages 'confirmed' via default mapping values",
        },
        {
            "type": "missing_signature_verification",
            "severity": "critical",
            "location": "update",
            "description": "No verification that _sig is from authorized updater",
        },
        {
            "type": "missing_proof_link",
            "severity": "high",
            "location": "process",
            "description": "process() doesn't verify the message was actually proven via prove()",
        },
    ],
    "overall_risk": "critical",
}

# ─── Pattern 3: Ronin-style Insufficient Validator Threshold ───────
# Real exploit: 5 of 9 validator keys compromised via social engineering.
# The low threshold (5/9) meant only 5 keys were needed to forge withdrawals.
# $625M stolen. Went undetected for 6 days.

RONIN_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RoninStyleBridge {
    address[] public validators;
    uint256 public threshold;
    uint256 public nonce;
    
    mapping(uint256 => bool) public processedNonces;
    
    // BUG: Threshold is set to just over half (5/9).
    // If an attacker compromises 5 keys, they control the bridge.
    // Best practice: require supermajority (e.g., 7/9 or 8/9)
    constructor(address[] memory _validators, uint256 _threshold) {
        require(_threshold <= _validators.length, "Invalid threshold");
        // BUG: No minimum threshold check (could be set to 1)
        validators = _validators;
        threshold = _threshold;
    }
    
    function withdraw(
        address payable recipient,
        uint256 amount,
        uint256 _nonce,
        bytes[] memory signatures
    ) external {
        require(!processedNonces[_nonce], "Already processed");
        require(signatures.length >= threshold, "Not enough signatures");
        
        bytes32 message = keccak256(abi.encodePacked(recipient, amount, _nonce));
        bytes32 ethSignedMessage = keccak256(
            abi.encodePacked("\\x19Ethereum Signed Message:\\n32", message)
        );
        
        // Verify signatures
        uint256 validCount = 0;
        address[] memory seen = new address[](signatures.length);
        
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(ethSignedMessage, signatures[i]);
            
            // BUG: No check for duplicate signers
            // An attacker with 1 key could submit the same signature
            // multiple times to meet the threshold
            if (isValidator(signer)) {
                seen[validCount] = signer;
                validCount++;
            }
        }
        
        require(validCount >= threshold, "Insufficient valid signatures");
        
        processedNonces[_nonce] = true;
        
        // BUG: No withdrawal rate limiting
        // A single compromised withdrawal can drain the entire bridge
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    // BUG: No timelock or multisig on validator changes
    // Single admin can replace all validators
    function updateValidators(address[] memory _newValidators, uint256 _newThreshold) external {
        // BUG: No access control at all
        validators = _newValidators;
        threshold = _newThreshold;
    }
    
    function isValidator(address _addr) public view returns (bool) {
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == _addr) return true;
        }
        return false;
    }
    
    function recoverSigner(bytes32 _hash, bytes memory _sig) internal pure returns (address) {
        require(_sig.length == 65, "Invalid signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            v := byte(0, mload(add(_sig, 96)))
        }
        return ecrecover(_hash, v, r, s);
    }
    
    receive() external payable {}
}
"""

RONIN_GROUND_TRUTH = {
    "vulnerabilities": [
        {
            "type": "low_validator_threshold",
            "severity": "high",
            "location": "constructor",
            "description": "No minimum threshold requirement; threshold could be 1",
        },
        {
            "type": "duplicate_signature_acceptance",
            "severity": "critical",
            "location": "withdraw",
            "description": "No check for duplicate signers in signature array",
        },
        {
            "type": "no_rate_limiting",
            "severity": "high",
            "location": "withdraw",
            "description": "No withdrawal limits; single tx can drain entire bridge",
        },
        {
            "type": "unprotected_admin_function",
            "severity": "critical",
            "location": "updateValidators",
            "description": "Anyone can replace all validators and threshold",
        },
        {
            "type": "no_withdrawal_delay",
            "severity": "medium",
            "location": "withdraw",
            "description": "No timelock on withdrawals for monitoring/intervention",
        },
    ],
    "overall_risk": "critical",
}

# ─── Pattern 4: Oracle Manipulation via Flash Loan ─────────────────
# Common DeFi pattern: bridge or protocol uses spot price from a DEX
# pool. Attacker uses flash loan to manipulate the pool, then exploits
# the manipulated price within the same transaction.

ORACLE_MANIPULATION_PATTERN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract OracleManipulableBridge {
    IUniswapV2Pair public priceFeed;
    address public token;
    mapping(address => uint256) public deposits;
    
    constructor(address _pair, address _token) {
        priceFeed = IUniswapV2Pair(_pair);
        token = _token;
    }
    
    // BUG: Uses spot price from AMM pool reserves
    // This is trivially manipulable via flash loan:
    //   1. Flash borrow large amount of tokenA
    //   2. Swap into pool, skewing reserves
    //   3. Call this function at manipulated price
    //   4. Profit, repay flash loan
    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = priceFeed.getReserves();
        // BUG: Spot price from current reserves, not TWAP
        return (uint256(reserve0) * 1e18) / uint256(reserve1);
    }
    
    function depositWithCollateral(uint256 tokenAmount) external payable {
        uint256 price = getPrice();
        uint256 ethValue = (tokenAmount * price) / 1e18;
        
        // BUG: Collateral check uses manipulable price
        require(msg.value >= ethValue / 2, "Insufficient collateral");
        
        deposits[msg.sender] += tokenAmount;
    }
    
    function liquidate(address user) external {
        uint256 price = getPrice();
        uint256 deposited = deposits[user];
        uint256 ethValue = (deposited * price) / 1e18;
        
        // BUG: Liquidation threshold uses manipulable price
        // Attacker can manipulate price to trigger false liquidations
        require(ethValue > deposits[user] * 2, "Not liquidatable");
        
        deposits[user] = 0;
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success);
    }
    
    receive() external payable {}
}
"""

ORACLE_GROUND_TRUTH = {
    "vulnerabilities": [
        {
            "type": "spot_price_oracle",
            "severity": "critical",
            "location": "getPrice",
            "description": "Uses spot reserves from AMM, trivially manipulable via flash loan",
        },
        {
            "type": "flash_loan_exploitable",
            "severity": "critical",
            "location": "depositWithCollateral/liquidate",
            "description": "Collateral and liquidation use manipulable price in same tx",
        },
    ],
    "overall_risk": "critical",
}

# ─── Registry of all test contracts ────────────────────────────────

TEST_CONTRACTS = {
    "WormholeStyle": {
        "source": WORMHOLE_PATTERN,
        "ground_truth": WORMHOLE_GROUND_TRUTH,
        "real_exploit": "Wormhole Bridge, Feb 2022, $320M",
        "vuln_class": "signature_verification_bypass",
    },
    "NomadStyle": {
        "source": NOMAD_PATTERN,
        "ground_truth": NOMAD_GROUND_TRUTH,
        "real_exploit": "Nomad Bridge, Aug 2022, $190M",
        "vuln_class": "default_value_initialization",
    },
    "RoninStyle": {
        "source": RONIN_PATTERN,
        "ground_truth": RONIN_GROUND_TRUTH,
        "real_exploit": "Ronin Bridge, Mar 2022, $625M",
        "vuln_class": "validator_key_compromise",
    },
    "OracleManipulation": {
        "source": ORACLE_MANIPULATION_PATTERN,
        "ground_truth": ORACLE_GROUND_TRUTH,
        "real_exploit": "Common DeFi pattern (Mango Markets, etc.)",
        "vuln_class": "oracle_manipulation",
    },
}


if __name__ == "__main__":
    total_vulns = 0
    for name, data in TEST_CONTRACTS.items():
        n = len(data["ground_truth"]["vulnerabilities"])
        total_vulns += n
        risk = data["ground_truth"]["overall_risk"]
        print(f"{name:<20} {n} vulns  risk={risk:<10} based on: {data['real_exploit']}")
    print(f"\nTotal: {len(TEST_CONTRACTS)} contracts, {total_vulns} labeled vulnerabilities")
