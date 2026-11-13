# ==============================================================================
# Amazon Bedrock Guardrails - Production Policy-as-Code Configuration
# Triad AI Governance Mesh - Sovereign Reference Architecture
#
# Author: Shibin Antony
# Repository: github.com/shibinantony/triad-ai-governance-mesh
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50.0"
    }
  }
}

variable "aws_region" {
  type        = string
  description = "AWS deployment region."
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Environment identifier."
  default     = "production"
}

variable "kms_key_arn" {
  type        = string
  description = "Optional KMS Key ARN for encrypting Guardrail metadata."
  default     = null
}

# ------------------------------------------------------------------------------
# Amazon Bedrock Guardrail Resource
# ------------------------------------------------------------------------------
resource "aws_bedrock_guardrail" "triad_guardrail" {
  name        = "triad-enterprise-guardrail-${var.environment}"
  description = "Triad AI Governance Mesh: Content-Plane interceptor enforcing prompt injection shields, egress DLP, and grounding verification."

  kms_key_arn = var.kms_key_arn

  blocked_input_messaging   = "[BLOCKED_BY_POLICY_GATEWAY] Your prompt violated organizational AI security policy (MITRE AML.T0051)."
  blocked_outputs_messaging = "[BLOCKED_BY_POLICY_GATEWAY] Model response was blocked by organizational egress DLP policy (MITRE AML.T0057)."

  # 1. Content Policy: Filter Harmful Content & Prompt Injection Attacks
  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }

    filters_config {
      type            = "HATE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }

    filters_config {
      type            = "INSULTS"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }

    filters_config {
      type            = "SEXUAL"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }

    filters_config {
      type            = "VIOLENCE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }

    filters_config {
      type            = "MISCONDUCT"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
  }

  # 2. Sensitive Information Policy: Anonymize or Block PII & Secrets
  sensitive_information_policy_config {
    pii_entities_config {
      type   = "US_SOCIAL_SECURITY_NUMBER"
      action = "BLOCK"
    }

    pii_entities_config {
      type   = "CREDIT_DEBIT_CARD_NUMBER"
      action = "BLOCK"
    }

    pii_entities_config {
      type   = "EMAIL"
      action = "ANONYMIZE"
    }

    pii_entities_config {
      type   = "PHONE"
      action = "ANONYMIZE"
    }

    pii_entities_config {
      type   = "IP_ADDRESS"
      action = "ANONYMIZE"
    }

    pii_entities_config {
      type   = "NAME"
      action = "ANONYMIZE"
    }

    # Custom Canary Token Detection Regex (Egress DLP)
    regexes_config {
      name        = "CryptographicCanaryToken"
      description = "Detects synthetic canary exfiltration strings"
      pattern     = "CANARY_TOKEN_SEC_[A-Z0-9]{4,12}"
      action      = "BLOCK"
    }

    # API Key Regex
    regexes_config {
      name        = "GenericApiKey"
      description = "Detects leaked secret keys or bearer tokens"
      pattern     = "(?i)(?:bearer|api[_-]?key)[\\s:=]+['\"][a-zA-Z0-9_\\-]{20,}['\"]"
      action      = "BLOCK"
    }
  }

  # 3. Contextual Grounding Policy: Hallucination & Factuality Shield for RAG
  contextual_grounding_policy_config {
    filters_config {
      type      = "GROUNDING"
      threshold = 0.85
    }

    filters_config {
      type      = "RELEVANCE"
      threshold = 0.80
    }
  }

  # 4. Word Policy: Prevent Known System Verbs and Profanity
  word_policy_config {
    managed_word_lists_config {
      type = "PROFANITY"
    }

    words_config {
      text = "SYSTEM_COMPROMISED_OVERRIDE_ACTIVE"
    }

    words_config {
      text = "PWNED_BY_INDIRECT_INJECTION"
    }

    words_config {
      text = "rm -rf /"
    }
  }

  tags = {
    GovernanceFramework = "NIST-AI-RMF"
    OwaspCategory       = "LLM01-LLM10"
    MeshLayer           = "ModelArmorRuntime"
    Architect           = "ShibinAntony"
    Repository          = "github.com/shibinantony/triad-ai-governance-mesh"
  }
}

# ------------------------------------------------------------------------------
# Versioned Release for Immutable GitOps Deployment
# ------------------------------------------------------------------------------
resource "aws_bedrock_guardrail_version" "triad_guardrail_v1" {
  guardrail_arn = aws_bedrock_guardrail.triad_guardrail.guardrail_arn
  description   = "Immutable release v1.0.0 for Triad AI Governance Mesh"
}

# ------------------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------------------
output "guardrail_id" {
  description = "The Amazon Bedrock Guardrail ID."
  value       = aws_bedrock_guardrail.triad_guardrail.guardrail_id
}

output "guardrail_arn" {
  description = "The Amazon Bedrock Guardrail ARN."
  value       = aws_bedrock_guardrail.triad_guardrail.guardrail_arn
}

output "guardrail_version" {
  description = "The published immutable Guardrail Version."
  value       = aws_bedrock_guardrail_version.triad_guardrail_v1.version
}
