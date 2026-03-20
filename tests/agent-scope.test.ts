import { describe, expect, it, beforeEach } from "vitest";
import { Cl, ClarityType } from "@stacks/transactions";

// Simnet addresses
const deployer = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";
const agent = "ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5";
const recipient = "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG";
const attacker = "ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC";

const contractName = `${deployer}.agent-scope`;

describe("AgentScope - Stacks Edition", () => {
  
  describe("Policy Management", () => {
    it("should allow owner to set agent policy", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "set-policy", 
        [Cl.principal(agent), Cl.uint(1000000), Cl.uint(200000), Cl.uint(144)],
        deployer
      );
      expect(result.result).toBeOk(Cl.bool(true));
    });

    it("should reject non-owner setting policy", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "set-policy",
        [Cl.principal(agent), Cl.uint(1000000), Cl.uint(200000), Cl.uint(144)],
        attacker
      );
      expect(result.result).toBeErr(Cl.uint(100)); // ERR-NOT-OWNER
    });

    it("should reject zero daily limit", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "set-policy",
        [Cl.principal(agent), Cl.uint(0), Cl.uint(200000), Cl.uint(144)],
        deployer
      );
      expect(result.result).toBeErr(Cl.uint(108)); // ERR-ZERO-AMOUNT
    });

    it("should reject per-tx limit > daily limit", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "set-policy",
        [Cl.principal(agent), Cl.uint(100), Cl.uint(200), Cl.uint(144)],
        deployer
      );
      expect(result.result).toBeErr(Cl.uint(104)); // ERR-PER-TX-LIMIT
    });

    it("should read policy back", () => {
      // Set policy first
      simnet.callPublicFn(
        "agent-scope", "set-policy",
        [Cl.principal(agent), Cl.uint(1000000), Cl.uint(200000), Cl.uint(144)],
        deployer
      );
      const result = simnet.callReadOnlyFn(
        "agent-scope", "get-policy", [Cl.principal(agent)], deployer
      );
      expect(result.result.type).toBe(ClarityType.OptionalSome);
    });
  });

  describe("Agent Execution", () => {
    beforeEach(() => {
      // Set up policy for agent
      simnet.callPublicFn(
        "agent-scope", "set-policy",
        [Cl.principal(agent), Cl.uint(1000000), Cl.uint(200000), Cl.uint(144)],
        deployer
      );
    });

    it("should allow transfer within limits", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(100000)],
        agent
      );
      expect(result.result).toBeOk(Cl.bool(true));
    });

    it("should block transfer exceeding per-tx limit", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(300000)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(104)); // ERR-PER-TX-LIMIT
    });

    it("should block transfer exceeding daily limit", () => {
      // Send max per-tx amount multiple times to exhaust daily
      simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(200000)],
        agent
      );
      simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(200000)],
        agent
      );
      simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(200000)],
        agent
      );
      simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(200000)],
        agent
      );
      simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(200000)],
        agent
      );
      // 5 x 200000 = 1000000 = daily limit hit
      const result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(1)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(103)); // ERR-DAILY-LIMIT
    });

    it("should block transfer when no policy exists", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(100)],
        attacker // no policy for attacker
      );
      expect(result.result).toBeErr(Cl.uint(107)); // ERR-NO-POLICY
    });

    it("should block zero amount transfer", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(0)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(108)); // ERR-ZERO-AMOUNT
    });
  });

  describe("Contract Whitelist", () => {
    beforeEach(() => {
      simnet.callPublicFn(
        "agent-scope", "set-policy",
        [Cl.principal(agent), Cl.uint(1000000), Cl.uint(200000), Cl.uint(144)],
        deployer
      );
    });

    it("should allow owner to whitelist contracts", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "whitelist-contract",
        [Cl.principal(agent), Cl.principal(recipient)],
        deployer
      );
      expect(result.result).toBeOk(Cl.bool(true));
    });

    it("should verify whitelist status", () => {
      simnet.callPublicFn(
        "agent-scope", "whitelist-contract",
        [Cl.principal(agent), Cl.principal(recipient)],
        deployer
      );
      const result = simnet.callReadOnlyFn(
        "agent-scope", "is-whitelisted",
        [Cl.principal(agent), Cl.principal(recipient)],
        deployer
      );
      expect(result.result).toStrictEqual(Cl.bool(true));
    });

    it("should block non-whitelisted contract calls", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "execute-contract-call",
        [Cl.principal(attacker), Cl.uint(100)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(105)); // ERR-NOT-WHITELISTED
    });

    it("should allow whitelisted contract calls", () => {
      simnet.callPublicFn(
        "agent-scope", "whitelist-contract",
        [Cl.principal(agent), Cl.principal(recipient)],
        deployer
      );
      const result = simnet.callPublicFn(
        "agent-scope", "execute-contract-call",
        [Cl.principal(recipient), Cl.uint(100)],
        agent
      );
      expect(result.result).toBeOk(Cl.bool(true));
    });
  });

  describe("Emergency Controls", () => {
    beforeEach(() => {
      simnet.callPublicFn(
        "agent-scope", "set-policy",
        [Cl.principal(agent), Cl.uint(1000000), Cl.uint(200000), Cl.uint(144)],
        deployer
      );
    });

    it("should block all transfers when paused", () => {
      simnet.callPublicFn(
        "agent-scope", "set-paused", [Cl.bool(true)], deployer
      );
      const result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(100)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(102)); // ERR-PAUSED
    });

    it("should resume after unpause", () => {
      simnet.callPublicFn(
        "agent-scope", "set-paused", [Cl.bool(true)], deployer
      );
      simnet.callPublicFn(
        "agent-scope", "set-paused", [Cl.bool(false)], deployer
      );
      const result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(100)],
        agent
      );
      expect(result.result).toBeOk(Cl.bool(true));
    });

    it("should permanently revoke agent", () => {
      simnet.callPublicFn(
        "agent-scope", "revoke-agent", [Cl.principal(agent)], deployer
      );
      const result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(100)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(106)); // ERR-AGENT-REVOKED
    });

    it("should only allow owner to pause", () => {
      const result = simnet.callPublicFn(
        "agent-scope", "set-paused", [Cl.bool(true)], attacker
      );
      expect(result.result).toBeErr(Cl.uint(100)); // ERR-NOT-OWNER
    });
  });

  describe("Jailbreak Scenario", () => {
    it("should survive a full jailbreak attack", () => {
      // Owner sets policy
      simnet.callPublicFn(
        "agent-scope", "set-policy",
        [Cl.principal(agent), Cl.uint(500000), Cl.uint(200000), Cl.uint(144)],
        deployer
      );

      // Normal operation — agent sends 100k (within limits)
      let result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(100000)],
        agent
      );
      expect(result.result).toBeOk(Cl.bool(true));

      // JAILBREAK: Agent tries to drain 10M
      result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(attacker), Cl.uint(10000000)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(104)); // BLOCKED: per-tx limit

      // JAILBREAK: Agent tries non-whitelisted contract
      result = simnet.callPublicFn(
        "agent-scope", "execute-contract-call",
        [Cl.principal(attacker), Cl.uint(100)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(105)); // BLOCKED: not whitelisted

      // JAILBREAK: Agent tries to exhaust daily budget
      simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(200000)],
        agent
      );
      simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(200000)],
        agent
      );
      // 100k + 200k + 200k = 500k = daily limit
      result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(1)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(103)); // BLOCKED: daily limit

      // Owner detects, hits panic button
      simnet.callPublicFn(
        "agent-scope", "set-paused", [Cl.bool(true)], deployer
      );
      result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(1)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(102)); // BLOCKED: paused

      // Owner revokes agent permanently
      simnet.callPublicFn(
        "agent-scope", "revoke-agent", [Cl.principal(agent)], deployer
      );
      simnet.callPublicFn(
        "agent-scope", "set-paused", [Cl.bool(false)], deployer
      );
      result = simnet.callPublicFn(
        "agent-scope", "execute-transfer",
        [Cl.principal(recipient), Cl.uint(1)],
        agent
      );
      expect(result.result).toBeErr(Cl.uint(106)); // BLOCKED: revoked

      // Verify stats
      const stats = simnet.callReadOnlyFn(
        "agent-scope", "get-stats", [], deployer
      );
      // Should have approved transfers and blocked attempts
      expect(stats.result.type).toBe(ClarityType.Tuple);
    });
  });
});
