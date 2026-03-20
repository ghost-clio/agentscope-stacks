;; AgentScope -- On-chain AI Agent Wallet Policy Enforcement for Stacks/Bitcoin
;; 
;; This contract enforces spending policies for autonomous AI agents.
;; The owner sets rules (daily limits, per-tx limits, contract whitelists).
;; The agent can only transact within those rules. The blockchain enforces them.
;;
;; "Even when the agent is compromised, the math says no."

;; ============================================================================
;; Error codes
;; ============================================================================
(define-constant ERR-NOT-OWNER (err u100))
;; Reserved: u101 (ERR-NOT-AGENT)
(define-constant ERR-PAUSED (err u102))
(define-constant ERR-DAILY-LIMIT (err u103))
(define-constant ERR-PER-TX-LIMIT (err u104))
(define-constant ERR-NOT-WHITELISTED (err u105))
(define-constant ERR-AGENT-REVOKED (err u106))
(define-constant ERR-NO-POLICY (err u107))
(define-constant ERR-ZERO-AMOUNT (err u108))
;; Reserved: u109 (ERR-ALREADY-ACTIVE), u110 (ERR-SESSION-EXPIRED)

;; ============================================================================
;; Data variables -- global state
;; ============================================================================
(define-data-var contract-owner principal tx-sender)
(define-data-var paused bool false)
(define-data-var total-blocked uint u0)
(define-data-var total-approved uint u0)

;; ============================================================================
;; Data maps -- per-agent state
;; ============================================================================

;; Agent policy: set by owner, enforced by contract
(define-map agent-policies
  principal  ;; agent address
  {
    daily-limit: uint,        ;; max STX per day (in microSTX)
    per-tx-limit: uint,       ;; max STX per transaction
    session-duration: uint,   ;; session length in blocks (~10 min per block)
    active: bool,             ;; whether agent is active
    revoked: bool             ;; permanently revoked
  }
)

;; Agent spending tracker: resets daily (by block height window)
(define-map agent-spending
  principal  ;; agent address
  {
    spent-today: uint,       ;; amount spent in current window
    window-start: uint,      ;; block height when window started
    tx-count: uint,          ;; total transactions executed
    last-tx-block: uint      ;; block of last transaction
  }
)

;; Contract whitelist: per-agent approved contracts
(define-map whitelisted-contracts
  { agent: principal, target: principal }
  bool
)

;; ============================================================================
;; Read-only functions
;; ============================================================================

(define-read-only (get-policy (agent principal))
  (map-get? agent-policies agent)
)

(define-read-only (get-spending (agent principal))
  (map-get? agent-spending agent)
)

(define-read-only (is-whitelisted (agent principal) (target principal))
  (default-to false (map-get? whitelisted-contracts { agent: agent, target: target }))
)

(define-read-only (is-paused)
  (var-get paused)
)

(define-read-only (get-owner)
  (var-get contract-owner)
)

(define-read-only (get-stats)
  {
    total-blocked: (var-get total-blocked),
    total-approved: (var-get total-approved),
    paused: (var-get paused),
    owner: (var-get contract-owner)
  }
)

;; Check remaining daily budget for an agent
(define-read-only (get-remaining-budget (agent principal))
  (let
    (
      (policy (unwrap! (map-get? agent-policies agent) (err u0)))
      (spending (default-to 
        { spent-today: u0, window-start: u0, tx-count: u0, last-tx-block: u0 }
        (map-get? agent-spending agent)))
      (window-size u144)  ;; ~144 blocks per day
      (current-block stacks-block-height)
    )
    (if (>= (- current-block (get window-start spending)) window-size)
      ;; Window expired -- full budget available
      (ok (get daily-limit policy))
      ;; Within window -- return remaining (saturating subtraction)
      (if (>= (get spent-today spending) (get daily-limit policy))
        (ok u0)
        (ok (- (get daily-limit policy) (get spent-today spending)))
      )
    )
  )
)

;; ============================================================================
;; Owner functions -- policy management
;; ============================================================================

;; Set or update an agent's spending policy
(define-public (set-policy
  (agent principal)
  (daily-limit uint)
  (per-tx-limit uint)
  (session-duration uint)
)
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (asserts! (> daily-limit u0) ERR-ZERO-AMOUNT)
    (asserts! (> per-tx-limit u0) ERR-ZERO-AMOUNT)
    (asserts! (<= per-tx-limit daily-limit) ERR-PER-TX-LIMIT)
    (map-set agent-policies agent {
      daily-limit: daily-limit,
      per-tx-limit: per-tx-limit,
      session-duration: session-duration,
      active: true,
      revoked: false
    })
    ;; Only initialize spending if agent is new (don't reset on policy updates)
    (match (map-get? agent-spending agent)
      existing-spending true  ;; already has spending data, keep it
      (map-set agent-spending agent {
        spent-today: u0,
        window-start: stacks-block-height,
        tx-count: u0,
        last-tx-block: u0
      })
    )
    (print { event: "policy-set", agent: agent, daily-limit: daily-limit, per-tx-limit: per-tx-limit })
    (ok true)
  )
)

;; Whitelist a contract for an agent
(define-public (whitelist-contract (agent principal) (target principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (map-set whitelisted-contracts { agent: agent, target: target } true)
    (print { event: "contract-whitelisted", agent: agent, target: target })
    (ok true)
  )
)

;; Remove a contract from whitelist
(define-public (remove-whitelist (agent principal) (target principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (map-delete whitelisted-contracts { agent: agent, target: target })
    (print { event: "contract-removed", agent: agent, target: target })
    (ok true)
  )
)

;; Emergency pause -- freeze ALL agent execution
(define-public (set-paused (new-paused-state bool))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (var-set paused new-paused-state)
    (print { event: "pause-toggled", paused: new-paused-state })
    (ok true)
  )
)

;; Permanently revoke an agent -- cannot be re-enabled without new policy
(define-public (revoke-agent (agent principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (match (map-get? agent-policies agent)
      policy
        (begin
          (map-set agent-policies agent (merge policy { active: false, revoked: true }))
          (print { event: "agent-revoked", agent: agent })
          (ok true)
        )
      ERR-NO-POLICY
    )
  )
)

;; Transfer ownership
(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (var-set contract-owner new-owner)
    (print { event: "ownership-transferred", new-owner: new-owner })
    (ok true)
  )
)

;; ============================================================================
;; Agent functions -- execute within policy bounds
;; ============================================================================

;; Execute a STX transfer within policy limits
(define-public (execute-transfer (recipient principal) (amount uint))
  (let
    (
      (agent tx-sender)
      (policy (unwrap! (map-get? agent-policies agent) ERR-NO-POLICY))
      (spending (default-to
        { spent-today: u0, window-start: u0, tx-count: u0, last-tx-block: u0 }
        (map-get? agent-spending agent)))
      (window-size u144)
      (current-block stacks-block-height)
    )
    ;; Check: not paused
    (asserts! (not (var-get paused)) ERR-PAUSED)
    
    ;; Check: agent is active and not revoked
    (asserts! (get active policy) ERR-AGENT-REVOKED)
    (asserts! (not (get revoked policy)) ERR-AGENT-REVOKED)
    
    ;; Check: amount > 0
    (asserts! (> amount u0) ERR-ZERO-AMOUNT)
    
    ;; Check: per-transaction limit
    (asserts! (<= amount (get per-tx-limit policy)) ERR-PER-TX-LIMIT)
    
    ;; Check: daily limit (with window reset)
    (let
      (
        (effective-spent 
          (if (>= (- current-block (get window-start spending)) window-size)
            u0  ;; Window expired, reset
            (get spent-today spending)
          ))
        (new-window-start
          (if (>= (- current-block (get window-start spending)) window-size)
            current-block
            (get window-start spending)
          ))
      )
      (asserts! (<= (+ effective-spent amount) (get daily-limit policy)) ERR-DAILY-LIMIT)
      
      ;; All checks passed -- execute transfer
      (try! (stx-transfer? amount agent recipient))
      
      ;; Update spending tracker
      (map-set agent-spending agent {
        spent-today: (+ effective-spent amount),
        window-start: new-window-start,
        tx-count: (+ (get tx-count spending) u1),
        last-tx-block: current-block
      })
      
      ;; Update stats
      (var-set total-approved (+ (var-get total-approved) u1))
      
      (print { 
        event: "transfer-executed", 
        agent: agent, 
        recipient: recipient, 
        amount: amount,
        remaining: (- (get daily-limit policy) (+ effective-spent amount))
      })
      (ok true)
    )
  )
)

;; Approve a contract call -- must be whitelisted + within daily limits
;; NOTE: This is a permission oracle, not a direct executor. Clarity's
;; contract-call? requires static dispatch (known at deploy time), so
;; dynamic agent->arbitrary contract calls must be composed externally.
;; The middleware checks approval here BEFORE executing the actual call.
(define-public (execute-contract-call (target principal) (amount uint))
  (let
    (
      (agent tx-sender)
      (policy (unwrap! (map-get? agent-policies agent) ERR-NO-POLICY))
      (spending (default-to
        { spent-today: u0, window-start: u0, tx-count: u0, last-tx-block: u0 }
        (map-get? agent-spending agent)))
      (window-size u144)
      (current-block stacks-block-height)
    )
    ;; Check: not paused
    (asserts! (not (var-get paused)) ERR-PAUSED)
    
    ;; Check: agent is active
    (asserts! (get active policy) ERR-AGENT-REVOKED)
    (asserts! (not (get revoked policy)) ERR-AGENT-REVOKED)
    
    ;; Check: target is whitelisted
    (asserts! (is-whitelisted agent target) ERR-NOT-WHITELISTED)
    
    ;; Check: amount > 0
    (asserts! (> amount u0) ERR-ZERO-AMOUNT)
    
    ;; Check: per-tx limit
    (asserts! (<= amount (get per-tx-limit policy)) ERR-PER-TX-LIMIT)
    
    ;; Check: daily limit (with window reset)
    (let
      (
        (effective-spent
          (if (>= (- current-block (get window-start spending)) window-size)
            u0
            (get spent-today spending)
          ))
        (new-window-start
          (if (>= (- current-block (get window-start spending)) window-size)
            current-block
            (get window-start spending)
          ))
      )
      (asserts! (<= (+ effective-spent amount) (get daily-limit policy)) ERR-DAILY-LIMIT)
      
      ;; Update spending tracker
      (map-set agent-spending agent {
        spent-today: (+ effective-spent amount),
        window-start: new-window-start,
        tx-count: (+ (get tx-count spending) u1),
        last-tx-block: current-block
      })
      
      ;; Update stats
      (var-set total-approved (+ (var-get total-approved) u1))
      
      (print {
        event: "contract-call-approved",
        agent: agent,
        target: target,
        amount: amount,
        remaining: (- (get daily-limit policy) (+ effective-spent amount))
      })
      (ok true)
    )
  )
)

;; ============================================================================
;; Policy violation logging (called by middleware layer)
;; ============================================================================
(define-public (log-violation (agent principal) (reason (string-ascii 64)) (amount uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-OWNER)
    (var-set total-blocked (+ (var-get total-blocked) u1))
    (print {
      event: "policy-violation",
      agent: agent,
      reason: reason,
      amount: amount,
      block: stacks-block-height
    })
    (ok true)
  )
)
