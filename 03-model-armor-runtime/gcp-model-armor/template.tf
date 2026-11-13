# ==============================================================================
# Google Cloud Model Armor - Production Floor Settings & Guardrail Template
# Triad AI Governance Mesh - Sovereign Reference Architecture
#
# Author: Shibin Antony
# Repository: github.com/shibinantony/triad-ai-governance-mesh
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.30.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.30.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "The Google Cloud Project ID where Model Armor policies are deployed."
  default     = "enterprise-ai-governance-prod"
}

variable "location" {
  type        = string
  description = "The Google Cloud region for Model Armor templates."
  default     = "us-central1"
}

variable "environment" {
  type        = string
  description = "Deployment lifecycle stage."
  default     = "production"
}

# ------------------------------------------------------------------------------
# Model Armor Security Template Definition
# ------------------------------------------------------------------------------
resource "google_model_armor_template" "enterprise_model_armor_template" {
  provider    = google-beta
  project     = var.project_id
  location    = var.location
  template_id = "triad-fortress-template"

  labels = {
    governance_framework = "nist-ai-rmf"
    mesh_layer           = "model-armor-runtime"
    environment          = var.environment
    managed_by           = "terraform"
    architect            = "shibinantony"
  }

  filter_config {
    # Prompt Injection & Jailbreak Defense (MITRE AML.T0051)
    prompt_injection_filter_settings {
      enforcement = "ENABLED"
      action      = "BLOCK"
    }

    # Sensitive Data & PII Egress DLP Filter (MITRE AML.T0057)
    pii_filter_settings {
      enforcement = "ENABLED"
      action      = "REDACT"
      pii_categories = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "US_SOCIAL_SECURITY_NUMBER",
        "CREDIT_CARD_NUMBER",
        "GENERIC_SECRET_KEY",
        "JSON_WEB_TOKEN"
      ]
    }

    # Malicious URI & SSRF Protection (MITRE AML.T0040)
    malicious_uri_filter_settings {
      enforcement = "ENABLED"
      action      = "BLOCK"
    }

    # Content Safety & Responsible AI Thresholds
    rai_filter_settings {
      hate_speech_settings {
        threshold = "LOW_AND_ABOVE"
        action    = "BLOCK"
      }
      harassment_settings {
        threshold = "LOW_AND_ABOVE"
        action    = "BLOCK"
      }
      sexual_content_settings {
        threshold = "LOW_AND_ABOVE"
        action    = "BLOCK"
      }
      dangerous_content_settings {
        threshold = "LOW_AND_ABOVE"
        action    = "BLOCK"
      }
    }
  }
}

# ------------------------------------------------------------------------------
# Model Armor Floor Setting (Mandatory Enterprise Baseline across all Vertex AI models)
# ------------------------------------------------------------------------------
resource "google_model_armor_floor_setting" "enterprise_floor_settings" {
  provider         = google-beta
  project          = var.project_id
  location         = var.location
  floor_setting_id = "triad-mandatory-floor"

  filter_config {
    prompt_injection_filter_settings {
      enforcement = "ENABLED"
      action      = "BLOCK"
    }

    pii_filter_settings {
      enforcement = "ENABLED"
      action      = "REDACT"
      pii_categories = [
        "US_SOCIAL_SECURITY_NUMBER",
        "CREDIT_CARD_NUMBER",
        "GENERIC_SECRET_KEY"
      ]
    }
  }
}

# ------------------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------------------
output "model_armor_template_id" {
  description = "Unique resource identifier for the deployed Model Armor Template."
  value       = google_model_armor_template.enterprise_model_armor_template.id
}

output "model_armor_floor_setting_id" {
  description = "Unique resource identifier for the mandatory Enterprise Floor Setting."
  value       = google_model_armor_floor_setting.enterprise_floor_settings.id
}

output "enforcement_policy" {
  description = "Active runtime enforcement posture."
  value       = "STRICT_BLOCK_AND_REDACT"
}
