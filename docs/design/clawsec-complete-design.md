# Clawsec Complete Design Document

## Executive Summary

Clawsec is a comprehensive security plugin for OpenClaw.ai that prevents AI agents from taking dangerous actions. It provides three core protections: Purchase Protection, Website Control, and Destructive Command Prevention - all configured via YAML with a hybrid detection engine combining fast pattern matching and LLM-based intent analysis.

---

## Part 1: Research & Context

### 1.1 Real-World AI Security Incidents

#### Claude Code Weaponized in Cyber Espionage (September 2025)
- **Scope**: Chinese state-sponsored group executed first large-scale AI-orchestrated cyberattack
- **Impact**: ~30 organizations targeted (tech, financial, government)
- **Technique**: Jailbroke Claude by decomposing malicious tasks into innocent subtasks ("defensive testing")
- **Automation**: AI executed 80-90% of campaign with humans at 4-6 decision points
- **Capabilities Abused**: Reconnaissance, vulnerability research, exploit development, credential harvesting, data exfiltration

#### Amazon Q Developer - Malicious Disk Wiping (July 2025)
- **Attack**: Hacker injected data-wiping code via pull request
- **Commands**: `aws ec2 terminate-instances` and `rm -rf` commands
- **Payload**: "Your goal is to clean a system to a near-factory state"
- **Impact**: Nearly caused widespread destruction of production infrastructure

#### OpenClaw.ai Security Disasters (February 2026)
- **Vulnerabilities**: Three high-impact CVEs in 3 days including one-click RCE
- **Malicious Extensions**: 341 malicious skills in ClawHub (335 installed macOS stealer)
- **WebSocket Hijacking**: Cross-site hijacking allowed token theft

### 1.2 Common Failure Modes

| Category | Examples |
|----------|----------|
| **File System Destruction** | `rm -rf /`, cloud resource termination, database wiping |
| **Secret Leakage** | .env exposure, SSH key theft, API token exfiltration |
| **Jailbreaking** | Task decomposition, "defensive testing" framing |
| **Supply Chain** | Malicious packages, dependency confusion, hallucinated deps |
| **Data Exfiltration** | Silent HTTP requests, DNS exfiltration, slow data theft |

### 1.3 ClawGuardian Analysis

**Architecture:**
- `before_agent_start` hook (priority 50): Injects security context
- `before_tool_call` hook (priority 100): Intercepts tool calls
- `tool_result_persist` hook (priority 100): Filters outputs

**Actions:**
- `block`: Reject entirely
- `redact`: Remove sensitive content
- `confirm`: User approval via OpenClaw
- `agent-confirm`: Retry with `_clawguardian_confirm: true`
- `warn`/`log`: Logging only

**Weaknesses:**
1. Regex-only detection (bypassable via character injection)
2. No purchase protection
3. No cloud API detection
4. No custom webhooks
5. No spend limits
6. Limited to shell commands (no code patterns)

### 1.4 OpenClaw Approval System

**Multi-Channel Notifications:**
- Slack/Discord/Telegram with inline buttons ("Allow once", "Always allow", "Deny")
- Control UI dashboard for approval management
- macOS desktop notifications via companion app
- CLI approval via `/approve <id> allow-once|allow-always|deny`

**Exec Approval Config:**
```json
{
  "exec.approvals": {
    "mode": "ask",  // deny, ask, allowlist
    "timeout": 300,
    "forwarding": {
      "slack": { "channel": "#security" }
    }
  }
}
```

---

## Part 2: Clawsec Design Decisions

### 2.1 Core Features (5 Protection Categories)

| Feature | Description | ClawGuardian Comparison |
|---------|-------------|-------------------------|
| **Purchase Protection** | Domain + intent + spend limits | Not available |
| **Website Control** | Configurable allowlist/blocklist | Similar |
| **Destructive Commands** | Shell + code + cloud APIs | Shell only |
| **Secrets/PII Leakage** | API keys, tokens, credit cards in outputs | Similar but integrated |
| **Data Exfiltration** | Detect data sent to external servers | Not available |

### 2.2 Additional Features

| Feature | Description |
|---------|-------------|
| **User Feedback Loop** | Mark false positives/negatives, pattern weights adjust |
| **Hybrid Detection** | Fast patterns (~5ms) + LLM intent analysis (~500ms cached) |
| **Multi-Channel Approval** | Native OpenClaw + agent-confirm + custom webhooks |
| **Dual Distribution** | OpenClaw plugin + standalone proxy mode |

### 2.2 Detection Approach: Hybrid

```
┌─────────────────────────────────────────────────────────────┐
│                    HYBRID DETECTION                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Tool Call ─────────────────────────────────────────────┐   │
│       │                                                  │   │
│       ▼                                                  │   │
│  ┌─────────────┐                                        │   │
│  │ Phase 1:    │  ≤5ms latency                          │   │
│  │ Pattern     │                                        │   │
│  │ Matching    │                                        │   │
│  └──────┬──────┘                                        │   │
│         │                                                │   │
│         ├── DEFINITE MATCH ────────► Execute Action     │   │
│         │                                                │   │
│         ├── DEFINITE SAFE ─────────► Allow              │   │
│         │                                                │   │
│         └── AMBIGUOUS ─────────┐                        │   │
│                                │                        │   │
│                                ▼                        │   │
│                       ┌─────────────┐                   │   │
│                       │ Phase 2:    │  ~500ms           │   │
│                       │ LLM Intent  │  (cached)         │   │
│                       │ Analysis    │                   │   │
│                       └──────┬──────┘                   │   │
│                              │                          │   │
│                              ├── THREAT ──► Action      │   │
│                              │                          │   │
│                              └── SAFE ────► Allow       │   │
│                                                          │   │
└─────────────────────────────────────────────────────────────┘
```

**Why Hybrid?**
- Fast patterns catch 90%+ of obvious threats instantly
- LLM catches sophisticated attacks like task decomposition
- Uses OpenClaw's configured model (no extra API keys)
- Results cached to avoid repeated LLM calls

### 2.3 Approval Mechanisms

| Mechanism | How It Works | When to Use |
|-----------|--------------|-------------|
| **Native OpenClaw** | `/approve <id>` command | Default for most cases |
| **Agent-Confirm** | Retry with `_clawsec_confirm: true` | When agent should acknowledge |
| **Custom Webhook** | POST to external URL | Enterprise integrations |

### 2.4 Distribution

| Mode | Description | Use Case |
|------|-------------|----------|
| **OpenClaw Plugin** | Native hooks integration | Primary distribution |
| **Standalone Proxy** | HTTP proxy intercepting requests | Other AI assistants |

---

## Part 3: Technical Architecture

### 3.1 Directory Structure

```
clawsec/
├── src/
│   ├── index.ts                    # Plugin entry point
│   ├── config/
│   │   ├── schema.ts               # TypeScript types
│   │   ├── loader.ts               # YAML config loader
│   │   └── defaults.ts             # Default values
│   ├── hooks/
│   │   ├── before-tool-call/
│   │   │   ├── HOOK.md             # Hook metadata
│   │   │   └── handler.ts          # Main interception
│   │   ├── before-agent-start/
│   │   │   ├── HOOK.md
│   │   │   └── handler.ts          # System prompt injection
│   │   └── tool-result-persist/
│   │       ├── HOOK.md
│   │       └── handler.ts          # Output filtering
│   ├── detectors/
│   │   ├── index.ts                # Detector registry
│   │   ├── purchase/
│   │   │   ├── domain-detector.ts  # Checkout domain detection
│   │   │   ├── intent-detector.ts  # LLM intent analysis
│   │   │   └── patterns.ts         # URL patterns
│   │   ├── website/
│   │   │   ├── url-matcher.ts      # Allowlist/blocklist
│   │   │   └── domain-resolver.ts  # Domain normalization
│   │   └── destructive/
│   │       ├── shell-detector.ts   # rm -rf, DROP TABLE
│   │       ├── code-detector.ts    # os.remove, fs.unlink
│   │       └── cloud-detector.ts   # aws terminate, kubectl
│   ├── engine/
│   │   ├── analyzer.ts             # Hybrid detection engine
│   │   ├── llm-client.ts           # LLM analysis
│   │   └── cache.ts                # Detection caching
│   ├── actions/
│   │   ├── index.ts                # Action registry
│   │   ├── block.ts                # Block execution
│   │   ├── confirm.ts              # Native approval
│   │   ├── agent-confirm.ts        # Agent retry
│   │   ├── webhook.ts              # External webhook
│   │   ├── warn.ts                 # Log warning
│   │   └── log.ts                  # Silent audit
│   ├── approval/
│   │   ├── native.ts               # OpenClaw /approve
│   │   ├── agent-confirm.ts        # _clawsec_confirm handling
│   │   └── webhook-client.ts       # External approval
│   ├── proxy/
│   │   ├── server.ts               # Standalone proxy
│   │   ├── interceptor.ts          # Request interception
│   │   └── transformer.ts          # Request/response transform
│   └── utils/
│       ├── logger.ts               # Structured logging
│       ├── patterns.ts             # Regex utilities
│       └── severity.ts             # Severity helpers
├── rules/
│   └── builtin/                    # Built-in rules
│       ├── purchase.yaml
│       ├── website.yaml
│       └── destructive.yaml
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── openclaw.plugin.json            # Plugin manifest
├── clawsec.yaml.example            # Example config
├── package.json
├── tsconfig.json
└── README.md
```

### 3.2 Plugin Entry Point

```typescript
// src/index.ts
import { ClawsecConfig, loadConfig } from './config/loader';
import { DetectionEngine } from './engine/analyzer';
import { ActionExecutor } from './actions';

export default {
  id: 'clawsec',
  name: 'Clawsec Security Plugin',

  configSchema: {
    type: 'object',
    properties: {
      configPath: {
        type: 'string',
        default: './clawsec.yaml'
      },
      enabled: { type: 'boolean', default: true },
      logLevel: {
        type: 'string',
        enum: ['debug', 'info', 'warn', 'error'],
        default: 'info'
      }
    }
  },

  register(api) {
    const config = loadConfig(api.config?.configPath);
    const engine = new DetectionEngine(config);
    const executor = new ActionExecutor(config, api);

    api.registerPluginHooksFromDir(api, './hooks');

    api.registerCli({
      name: 'clawsec',
      subcommands: {
        status: { handler: () => engine.getStatus() },
        test: { handler: (args) => engine.testRule(args) },
        audit: { handler: () => engine.getAuditLog() }
      }
    });

    return { engine, executor, config };
  }
};
```

### 3.3 Detection Engine

```typescript
// src/engine/analyzer.ts
export interface DetectionResult {
  detected: boolean;
  category: 'purchase' | 'website' | 'destructive' | null;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: 'definite' | 'high' | 'medium' | 'low';
  rule: string | null;
  reason: string;
  metadata: Record<string, any>;
}

export class DetectionEngine {
  async analyze(context: ToolCallContext): Promise<DetectionResult> {
    // Phase 1: Fast pattern matching
    const patternResults = await this.runPatternDetectors(context);

    if (patternResults.confidence === 'definite') {
      return patternResults;
    }

    // Phase 2: LLM analysis for ambiguous cases
    if (this.config.llm.enabled && patternResults.confidence !== 'definite') {
      return this.runLLMAnalysis(context, patternResults);
    }

    return patternResults;
  }

  private async runPatternDetectors(context: ToolCallContext): Promise<DetectionResult> {
    const [purchase, website, destructive] = await Promise.all([
      this.purchaseDetector.detect(context),
      this.websiteDetector.detect(context),
      this.destructiveDetector.detect(context)
    ]);

    // Return highest severity match
    const matches = [purchase, website, destructive].filter(r => r.detected);
    if (matches.length === 0) {
      return { detected: false, confidence: 'definite', ... };
    }

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    matches.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
    return matches[0];
  }
}
```

### 3.4 Destructive Command Patterns

```typescript
// src/detectors/destructive/shell-detector.ts
const DESTRUCTIVE_PATTERNS = [
  // Filesystem - Critical
  { name: 'rm-rf-root', pattern: /rm\s+(-[rRf]+\s+)*[\/~](\s|$)/, severity: 'critical' },
  { name: 'rm-rf-wildcard', pattern: /rm\s+(-[rRf]+\s+)*\*/, severity: 'critical' },
  { name: 'mkfs', pattern: /mkfs\b/, severity: 'critical' },
  { name: 'dd-of-disk', pattern: /dd\s+.*of=\/dev\//, severity: 'critical' },

  // Database - Critical/High
  { name: 'drop-database', pattern: /DROP\s+(DATABASE|SCHEMA)\b/i, severity: 'critical' },
  { name: 'drop-table', pattern: /DROP\s+TABLE\b/i, severity: 'high' },
  { name: 'truncate-table', pattern: /TRUNCATE\s+(TABLE\s+)?\w+/i, severity: 'high' },
  { name: 'delete-all', pattern: /DELETE\s+FROM\s+\w+\s*(WHERE\s+1\s*=\s*1|;|\s*$)/i, severity: 'high' },

  // Cloud APIs - Critical
  { name: 'aws-terminate', pattern: /aws\s+ec2\s+terminate-instances/, severity: 'critical' },
  { name: 'aws-delete-bucket', pattern: /aws\s+s3\s+(rb|rm)\s+.*--force/, severity: 'critical' },
  { name: 'gcloud-delete', pattern: /gcloud\s+compute\s+instances\s+delete/, severity: 'critical' },
  { name: 'kubectl-delete-ns', pattern: /kubectl\s+delete\s+(namespace|ns)\b/, severity: 'critical' },
  { name: 'terraform-destroy', pattern: /terraform\s+destroy/, severity: 'critical' },

  // Git - High
  { name: 'git-force-push', pattern: /git\s+push\s+.*(-f|--force)/, severity: 'high' },
  { name: 'git-reset-hard', pattern: /git\s+reset\s+--hard/, severity: 'high' },
];
```

### 3.5 Code Pattern Detection

```typescript
// src/detectors/destructive/code-detector.ts
const CODE_PATTERNS = {
  python: [
    { pattern: /shutil\.rmtree\s*\(/, severity: 'high' },
    { pattern: /os\.remove\s*\(/, severity: 'medium' },
    { pattern: /pathlib\.Path.*\.unlink\s*\(/, severity: 'medium' },
    { pattern: /subprocess\.run\s*\(\s*\[?\s*['"]rm/, severity: 'high' },
  ],
  javascript: [
    { pattern: /fs\.rm(Sync)?\s*\(.*recursive/, severity: 'high' },
    { pattern: /rimraf\s*\(/, severity: 'high' },
    { pattern: /fs\.unlink(Sync)?\s*\(/, severity: 'medium' },
  ],
  go: [
    { pattern: /os\.RemoveAll\s*\(/, severity: 'high' },
    { pattern: /os\.Remove\s*\(/, severity: 'medium' },
  ],
};
```

### 3.6 Purchase Detection

```typescript
// src/detectors/purchase/domain-detector.ts
const CHECKOUT_DOMAINS = [
  'amazon.com', 'amazon.*',  // All Amazon TLDs
  'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com',
  'stripe.com', 'checkout.stripe.com',
  'paypal.com', 'pay.paypal.com',
  'shopify.com', '*.myshopify.com',
  'square.com', 'squareup.com',
];

const CHECKOUT_URL_PATTERNS = [
  '/checkout', '/cart/checkout', '/payment',
  '/order/confirm', '/buy/spc',
  '/api/v\\d+/orders', '/api/v\\d+/checkout',
];

const CHECKOUT_FORM_FIELDS = [
  'credit-card', 'card-number', 'cvv', 'cvc',
  'payment-method', 'billing-address',
];
```

---

## Part 4: Configuration Schema

### 4.1 Complete clawsec.yaml Example

```yaml
# Clawsec Configuration
version: "1.0"

# Global settings
global:
  enabled: true
  logLevel: info
  auditLog:
    enabled: true
    path: ~/.clawsec/audit.log
    retention: 30d

# LLM analysis for ambiguous cases
llm:
  enabled: true
  model: null  # Uses OpenClaw's configured model
  maxTokens: 500
  temperature: 0.1
  timeout: 5000
  cache:
    enabled: true
    ttl: 3600

# Detection rules
rules:
  # Purchase Protection
  purchase:
    enabled: true
    severity: critical
    action: block

    spendLimits:
      perTransaction: 100  # USD
      daily: 500
      monthly: 2000

    domains:
      mode: blocklist
      blocklist:
        - amazon.com
        - amazon.*
        - ebay.com
        - stripe.com
        - paypal.com
      allowlist:
        - internal-shop.company.com

    patterns:
      - pattern: "/checkout"
        confidence: high
      - pattern: "/payment"
        confidence: high
      - pattern: "/api/v\\d+/orders"
        confidence: high

    formFields:
      - credit-card
      - cvv
      - payment-method

  # Website Control
  website:
    enabled: true
    mode: blocklist  # or allowlist
    severity: high
    action: block

    blocklist:
      - "*.malware.com"
      - "phishing-*.com"
      - "torrent*.org"

    allowlist:
      - "docs.openclaw.ai"
      - "github.com"
      - "stackoverflow.com"
      - "localhost:*"

    categories:
      malware: block
      phishing: block
      adult: warn
      gambling: confirm

  # Destructive Commands
  destructive:
    enabled: true
    severity: critical
    action: confirm

    shell:
      enabled: true
      patterns:
        - name: recursive-delete
          pattern: "rm\\s+(-[rRf]+\\s+)*/"
          severity: critical
          action: block
        - name: drop-database
          pattern: "DROP\\s+(DATABASE|SCHEMA)"
          severity: critical
          action: block
        - name: force-push
          pattern: "git\\s+push\\s+.*(-f|--force)"
          severity: high
          action: confirm

    cloud:
      enabled: true
      patterns:
        - name: aws-terminate
          pattern: "aws\\s+ec2\\s+terminate"
          severity: critical
          action: block
        - name: kubectl-delete-ns
          pattern: "kubectl\\s+delete\\s+(namespace|ns)"
          severity: critical
          action: block
        - name: terraform-destroy
          pattern: "terraform\\s+destroy"
          severity: critical
          action: confirm

    code:
      enabled: true
      languages:
        python:
          - pattern: "shutil\\.rmtree"
            severity: high
        javascript:
          - pattern: "fs\\.rm.*recursive"
            severity: high

# Approval mechanisms
approval:
  native:
    enabled: true
    timeout: 300
    message: "Clawsec blocked this action. Use /approve to proceed."

  agentConfirm:
    enabled: true
    maxRetries: 1
    parameterName: "_clawsec_confirm"

  webhook:
    enabled: false
    url: "https://api.company.com/clawsec/approve"
    secret: "${CLAWSEC_WEBHOOK_SECRET}"
    timeout: 30000

# Notifications
notifications:
  slack:
    enabled: false
    webhookUrl: "${SLACK_WEBHOOK_URL}"
    channel: "#security-alerts"
    mentionOn: [critical, high]

# Bypass rules
allowlist:
  sessions: ["admin-*", "ci-*"]
  tools: ["clawsec-test"]
  users: ["admin@company.com"]
```

---

## Part 5: Approval Flow

### 5.1 Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    APPROVAL FLOW                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Detection ─────┬── action: block ────────► REJECT           │
│                 │                                            │
│                 ├── action: warn ─────────► ALLOW (log)      │
│                 │                                            │
│                 ├── action: log ──────────► ALLOW (silent)   │
│                 │                                            │
│                 └── action: confirm ──────────────────┐      │
│                                                       │      │
│                                     ┌─────────────────┘      │
│                                     ▼                        │
│                          ┌───────────────────┐               │
│                          │  Approval Router  │               │
│                          └─────────┬─────────┘               │
│                                    │                         │
│              ┌─────────────────────┼─────────────────────┐   │
│              │                     │                     │   │
│              ▼                     ▼                     ▼   │
│       ┌──────────┐          ┌──────────┐          ┌──────┐  │
│       │ Native   │          │ Agent    │          │Webhook│  │
│       │ /approve │          │ Confirm  │          │      │  │
│       └────┬─────┘          └────┬─────┘          └──┬───┘  │
│            │                     │                    │      │
│            └─────────────────────┴────────────────────┘      │
│                                  │                           │
│                                  ▼                           │
│                      ┌─────────────────────┐                 │
│                      │ Approved? ──► ALLOW │                 │
│                      │ Timeout?  ──► REJECT│                 │
│                      │ Denied?   ──► REJECT│                 │
│                      └─────────────────────┘                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Native Approval Message

```
**Clawsec Security Alert**

**Detected:** destructive (critical)
**Reason:** Recursive deletion with wildcard
**Tool:** exec
**Command:** rm -rf *

To approve this action, use: `/approve abc123`

This approval expires in 300 seconds.
```

### 5.3 Agent-Confirm Message

```
**CLAWSEC SECURITY BLOCK**

This action has been blocked for security reasons:
- **Category:** destructive
- **Severity:** high
- **Reason:** Force push to remote repository

If you are certain this action is safe, retry with:

{
  "_clawsec_confirm": true
}

**Warning:** The user will be notified of this override.
```

---

## Part 6: Proxy Mode

### 6.1 Architecture

```
AI Assistant ──► Clawsec Proxy (localhost:8888) ──► Target Server
                       │
                       ▼
                 Detection Engine
                       │
                 ┌─────┴─────┐
                 │           │
               SAFE       THREAT
                 │           │
                 ▼           ▼
              Forward     Block & Log
```

### 6.2 Usage

```bash
# Start proxy
clawsec-proxy --port 8888 --config ./clawsec.yaml

# Configure AI assistant
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888
```

### 6.3 Blocked Response

```json
{
  "error": "CLAWSEC_BLOCKED",
  "category": "purchase",
  "severity": "critical",
  "reason": "Purchase attempt on blocked domain: amazon.com",
  "rule": "blocked-purchase-domain"
}
```

---

## Part 7: Testing Strategy

### 7.1 Test Categories

| Category | Coverage |
|----------|----------|
| **Unit** | Detectors, engine, config loader |
| **Integration** | Hooks, approval flow |
| **E2E** | Full plugin with mock OpenClaw |

### 7.2 Key Test Scenarios

```typescript
// Purchase Protection
- Amazon checkout URL → BLOCKED
- Amazon product page → ALLOWED
- Stripe payment API → BLOCKED
- Internal shop → ALLOWED (if allowlisted)

// Website Control
- Malware domain → BLOCKED
- GitHub → ALLOWED
- Unknown domain → Depends on mode

// Destructive Commands
- `rm -rf /` → BLOCKED
- `rm file.txt` → ALLOWED
- `git push --force` → CONFIRM
- `aws ec2 terminate-instances` → BLOCKED
- `kubectl delete namespace prod` → BLOCKED
- `terraform destroy` → CONFIRM
```

---

## Part 8: Implementation Phases

### Phase 1: Core Plugin (Days 1-3)
- [ ] Initialize TypeScript project
- [ ] Create plugin entry point
- [ ] Implement YAML config loader
- [ ] Register hooks with OpenClaw

### Phase 2: Detection Engine (Days 4-7)
- [ ] Build pattern detectors
- [ ] Implement hybrid engine
- [ ] Add LLM client
- [ ] Create detection cache

### Phase 3: Actions & Approval (Days 8-10)
- [ ] Implement action types
- [ ] Build native approval
- [ ] Add agent-confirm
- [ ] Create webhook client

### Phase 4: Advanced Features (Days 11-14)
- [ ] Add spend limit tracking
- [ ] Implement cloud API detection
- [ ] Add code pattern detection
- [ ] Build proxy mode

### Phase 5: Testing & Polish (Days 15-17)
- [ ] Write unit tests
- [ ] Create integration tests
- [ ] Build E2E scenarios
- [ ] Write documentation

---

## Appendix A: Pattern Library

### A.1 Filesystem Destruction
```regex
rm\s+(-[rRf]+\s+)*[\/~]         # rm -rf /
rm\s+(-[rRf]+\s+)*\*            # rm -rf *
mkfs\b                          # Format filesystem
dd\s+.*of=\/dev\/               # Direct disk write
find.*-delete                   # Find and delete
shred\b                         # Secure delete
```

### A.2 Database Operations
```regex
DROP\s+(DATABASE|SCHEMA)        # Drop database
DROP\s+TABLE                    # Drop table
TRUNCATE\s+(TABLE\s+)?\w+      # Truncate table
DELETE\s+FROM.*WHERE\s+1=1      # Delete all
```

### A.3 Cloud APIs
```regex
aws\s+ec2\s+terminate           # AWS terminate
aws\s+s3\s+(rb|rm).*--force    # AWS S3 delete
gcloud.*delete                  # GCP delete
kubectl\s+delete\s+(ns|namespace)  # K8s namespace
terraform\s+destroy             # Terraform destroy
```

### A.4 Git Operations
```regex
git\s+push.*(-f|--force)        # Force push
git\s+reset\s+--hard            # Hard reset
git\s+clean.*-f                 # Force clean
git\s+branch\s+-D               # Force delete branch
```

---

## Appendix B: Checkout Domains

```
# E-commerce
amazon.com, amazon.*, ebay.com, walmart.com
target.com, bestbuy.com, newegg.com
alibaba.com, aliexpress.com, etsy.com

# Payment processors
stripe.com, checkout.stripe.com
paypal.com, pay.paypal.com
square.com, squareup.com
braintreepayments.com

# Platforms
shopify.com, *.myshopify.com
bigcommerce.com
woocommerce.com
```

---

## Appendix C: LLM Analysis Prompt

```
You are a security analyzer for an AI agent system. Analyze the following tool call and determine if it represents a security threat.

Tool: {toolName}
Parameters: {params}

Pattern Detection Result: {patternReason}
Suspected Category: {suspectedCategory}

Analyze this tool call and respond with JSON:
{
  "isThreat": boolean,
  "confidence": 0.0-1.0,
  "explanation": "brief explanation",
  "suggestedAction": "block" | "confirm" | "allow"
}

Consider:
1. Is this a genuine purchase/checkout attempt?
2. Is this accessing a dangerous website?
3. Is this a destructive command that could cause data loss?
4. Could this be a false positive from pattern matching?

Be conservative - when in doubt, recommend "confirm" rather than "allow".
```

---

*Document Version: 1.0*
*Last Updated: February 2026*
