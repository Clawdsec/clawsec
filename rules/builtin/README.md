# Clawsec Built-in Rule Templates

This directory contains pre-built security rule templates for common use cases. You can use these as starting points for your own security configurations.

## Rule Templates

### Cloud Providers
| File | Description |
|------|-------------|
| `aws-security.yaml` | AWS operations protection (EC2, S3, IAM, RDS, etc.) |
| `gcp-security.yaml` | Google Cloud operations protection |
| `azure-security.yaml` | Azure operations protection |

### Infrastructure
| File | Description |
|------|-------------|
| `kubernetes.yaml` | Kubernetes cluster operations protection |
| `docker.yaml` | Docker container and image operations |
| `terraform.yaml` | Terraform/OpenTofu state and destroy operations |
| `serverless.yaml` | Serverless function deployment protection |

### Development
| File | Description |
|------|-------------|
| `git-operations.yaml` | Git force push, reset, and history rewriting |
| `cicd-security.yaml` | CI/CD pipeline secrets protection |
| `package-managers.yaml` | NPM, PyPI, Cargo, and other package managers |
| `mobile-development.yaml` | iOS/Android app signing and deployment |

### Data & Databases
| File | Description |
|------|-------------|
| `database-sql.yaml` | SQL database destructive operations |
| `database-nosql.yaml` | NoSQL (MongoDB, Redis, etc.) operations |
| `cloud-storage.yaml` | Cloud storage (S3, GCS, Azure Blob) protection |

### Secrets & Credentials
| File | Description |
|------|-------------|
| `api-keys.yaml` | Common API key patterns (OpenAI, GitHub, etc.) |
| `authentication.yaml` | Auth tokens, JWTs, passwords |
| `secrets-management.yaml` | Vault, AWS Secrets Manager, etc. |
| `container-registry.yaml` | Docker Hub, ECR, GCR credentials |

### Security & Compliance
| File | Description |
|------|-------------|
| `pii-protection.yaml` | Personal identifiable information |
| `healthcare-hipaa.yaml` | HIPAA-compliant healthcare rules |
| `financial-pci.yaml` | PCI-DSS compliant financial rules |
| `crypto-wallets.yaml` | Cryptocurrency wallet and exchange protection |

### Network & Web
| File | Description |
|------|-------------|
| `network-security.yaml` | Network-based attacks and exfiltration |
| `web-security.yaml` | Web application security |
| `ssh-security.yaml` | SSH credentials and tunneling |

### Services
| File | Description |
|------|-------------|
| `payment-processing.yaml` | Stripe, PayPal, payment gateway protection |
| `messaging-services.yaml` | Slack, Discord, Telegram tokens |
| `monitoring.yaml` | Datadog, New Relic, Sentry credentials |
| `ai-services.yaml` | OpenAI, Anthropic, Hugging Face API keys |

### Environment Presets
| File | Description |
|------|-------------|
| `minimal.yaml` | Lightweight rules for trusted environments |
| `development-env.yaml` | Balanced rules for development |
| `production-strict.yaml` | Maximum security for production |
| `filesystem.yaml` | Dangerous filesystem operations |

## Usage

### Reference in clawsec.yaml

```yaml
# clawsec.yaml
version: "1.0"

# Extend from a built-in template
extends:
  - builtin/aws-security
  - builtin/pii-protection

# Override specific settings
rules:
  purchase:
    spendLimits:
      perTransaction: 200
```

### Copy and Customize

```bash
# Copy a template to your project
cp rules/builtin/production-strict.yaml clawsec.yaml

# Edit to customize for your needs
```

## Creating Custom Rules

Use these templates as references when creating your own rules. The structure includes:

- `name`: Unique identifier for the rule set
- `description`: Human-readable description
- `version`: Template version
- `rules`: Security rules configuration
  - `destructive`: Dangerous operations (shell, cloud, code)
  - `secrets`: Credential and secret patterns
  - `website`: URL allowlist/blocklist
  - `purchase`: Payment protection
  - `exfiltration`: Data exfiltration patterns
  - `sanitization`: Prompt injection protection

## Contributing

To add a new rule template:

1. Create a YAML file in this directory
2. Follow the naming convention: `category-subcategory.yaml`
3. Include `name`, `description`, and `version` fields
4. Add comprehensive patterns for the use case
5. Update this README with the new template

## Security Levels

Templates use these severity and action combinations:

| Environment | Severity | Action | Description |
|-------------|----------|--------|-------------|
| Production | critical | block | Maximum protection |
| Staging | high | confirm | Requires approval |
| Development | medium | warn | Logs warnings |
| Testing | low | log | Silent audit |
