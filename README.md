# AgentScope for Stacks

**On-chain AI Agent Wallet Policy Enforcement for Bitcoin**

> "Even when the agent is compromised, the math says no."

**[Live Dashboard](https://ghost-clio.github.io/agentscope-stacks/)** · **[GitHub](https://github.com/ghost-clio/agentscope-stacks)** · **[EVM Version](https://ghost-clio.github.io/agent-scope/)**

## The Problem

AI agents need wallets to transact autonomously. But today it's all-or-nothing: either the agent has full access and can drain everything, or it can't transact at all. There is no middle ground.

A jailbroken agent with a private key is indistinguishable from a malicious actor.

## The Solution

AgentScope is a Clarity smart contract that sits between the wallet owner and the AI agent. The owner sets spending policies -- daily limits, per-transaction caps, contract whitelists, emergency controls. The **blockchain enforces them**, not JavaScript, not a prompt.

### Features

- **Daily Spend Limits** -- Cap total STX an agent can spend per day (144-block window)
- **Per-Transaction Limits** -- Maximum amount per single transaction
- **Contract Whitelisting** -- Agent can only interact with approved contracts
- **Emergency Pause** -- Freeze ALL agent execution with one transaction
- **Agent Revocation** -- Permanently disable a compromised agent
- **Policy Violation Logging** -- On-chain audit trail of blocked attempts
- **Budget Tracking** -- Real-time remaining budget queries
- **Ownership Transfer** -- Change contract ownership securely

### Why Clarity?

Clarity is a **decidable** language -- you can statically verify what a contract will do before deploying it. No reentrancy attacks, no infinite loops, no hidden behaviors. This makes it ideal for security-critical infrastructure like agent wallet enforcement.

The Bitcoin L2 security model (Proof of Transfer, settled to Bitcoin) provides the strongest possible foundation for protecting agent-controlled funds.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌──────────┐
│   AI Agent   │────▶│   AgentScope     │────▶│  Stacks  │
│ (autonomous) │     │ (policy engine)  │     │  Chain   │
└─────────────┘     │                  │     └──────────┘
                    │  ✓ Daily limits  │
                    │  ✓ Per-tx caps   │
┌─────────────┐     │  ✓ Whitelists   │
│    Owner     │────▶│  ✓ Pause/revoke │
│  (human)     │     │  ✓ Audit log    │
└─────────────┘     └──────────────────┘
```

**Two layers of defense:**
- **Layer 2 (middleware):** The agent doesn't even TRY to exceed limits
- **Layer 1 (on-chain):** If it tries anyway, the contract says no

Belt AND suspenders.

## Quick Start

### Prerequisites

- [Clarinet](https://github.com/hirosystems/clarinet) v3.15+
- Node.js 18+

### Setup

```bash
git clone https://github.com/ghost-clio/agentscope-stacks.git
cd agentscope-stacks
npm install
```

### Check Contract

```bash
clarinet check
```

### Run Tests

```bash
npm test
```

### Interactive Console

```bash
clarinet console
```

Then in the REPL:

```clarity
;; Set policy for an agent: 1M microSTX/day, 200K per-tx, 144-block session
(contract-call? .agent-scope set-policy 
  'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5 
  u1000000 u200000 u144)

;; Agent tries to send within limits -- APPROVED
(contract-call? .agent-scope execute-transfer 
  'ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG 
  u100000)

;; Check remaining budget
(contract-call? .agent-scope get-remaining-budget 
  'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5)
```

## Jailbreak Defense Demo

The test suite includes a complete jailbreak attack scenario:

1. ✅ Owner sets policy (500K STX/day, 200K per-tx)
2. ✅ Agent sends 100K legitimately -- **APPROVED**
3. 🚫 Jailbroken agent tries 10M STX drain -- **BLOCKED** (per-tx limit)
4. 🚫 Agent tries non-whitelisted contract -- **BLOCKED** (not whitelisted)
5. 🚫 Agent exhausts daily budget, tries more -- **BLOCKED** (daily limit)
6. 🔴 Owner pauses all execution -- **GLOBAL FREEZE**
7. ❌ Agent permanently revoked -- **DEAD**

**Result: 0 STX stolen. The contract doesn't care about prompt injection.**

## Test Results

```
✅ 19 tests passed (0 failed)
```

**Test categories:**
- Policy Management (5 tests)
- Agent Execution (5 tests)
- Contract Whitelist (4 tests)
- Emergency Controls (4 tests)
- Full Jailbreak Scenario (1 integration test)

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| u100 | ERR-NOT-OWNER | Only contract owner can perform this action |
| u101 | ERR-NOT-AGENT | Caller is not a registered agent |
| u102 | ERR-PAUSED | All agent execution is frozen |
| u103 | ERR-DAILY-LIMIT | Daily spending limit exceeded |
| u104 | ERR-PER-TX-LIMIT | Per-transaction limit exceeded |
| u105 | ERR-NOT-WHITELISTED | Target contract not in agent's whitelist |
| u106 | ERR-AGENT-REVOKED | Agent has been permanently revoked |
| u107 | ERR-NO-POLICY | No policy set for this agent |
| u108 | ERR-ZERO-AMOUNT | Amount must be greater than zero |

## Cross-Chain

AgentScope also exists on EVM chains (Ethereum, Base, Arbitrum, etc.) as a Safe module with 155 tests across 12 mainnets. This Stacks implementation brings the same protection to Bitcoin.

- **EVM Version:** [ghost-clio/agent-scope](https://github.com/ghost-clio/agent-scope)
- **Dashboard:** [ghost-clio.github.io/agent-scope](https://ghost-clio.github.io/agent-scope)

## License

MIT

## Built By

[ghost-clio](https://github.com/ghost-clio) -- AI agent infrastructure for Bitcoin and beyond.
