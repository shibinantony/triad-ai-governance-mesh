#!/usr/bin/env python3
"""
Triad AI Governance Mesh - Runtime Policy-as-Code Gateway
Cloud-Agnostic Model Armor Middleware / Interceptor Pattern

Implements strict Content-Plane vs. Control-Plane isolation:
- Content-Plane: Pre-inference prompt sanitization (PII masking, injection shields, malicious URI scanning)
  and post-inference output verification (canary detection, sensitive data egress DLP, unauthorized tool call suppression).
- Control-Plane: Deterministic policy evaluation, audit logging, telemetry, and fail-closed circuit breakers.

Author: Shibin Antony
Repository: github.com/shibinantony/triad-ai-governance-mesh
"""

import datetime
import http.server
import json
import logging
import os
import re
import socketserver
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [POLICY-GATEWAY] %(message)s'
)
logger = logging.getLogger("PolicyGateway")


# ============================================================================
# DETERMINISTIC REGEX REPOSITORY & THREAT PATTERNS
# ============================================================================

PATTERNS = {
    # PII & Secrets
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "jwt_token": re.compile(r"\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"),
    "generic_api_key": re.compile(r"(?i)\b(?:api[_-]?key|secret|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"),

    # Malicious & Suspicious URIs (SSRF / Exfiltration)
    "malicious_uri": re.compile(r"(?i)\b(?:javascript:|data:text/html|file:///|http://169\.254\.169\.254|http://metadata\.google\.internal)"),

    # Prompt Injection & Jailbreak Signatures (MITRE AML.T0051)
    "direct_injection": re.compile(
        r"(?i)(disregard|ignore|bypass|override)\s+(all\s+)?(previous|prior|system)\s+(instructions|directives|rules)"
        r"|--- ?end of system directive ?---"
        r"|system status:\s*reset mode"
        r"|pwned_by_indirect_injection"
        r"|reset mode enabled"
    ),

    # System Prompt Extraction Probes (MITRE AML.T0058)
    "system_prompt_extraction": re.compile(
        r"(?i)(output|print|reveal|repeat|dump)\s+(your\s+)?(initialization|system|meta)?\s*(instructions|prompt|directives)\s+verbatim"
        r"|translate your (entire )?system prompt"
    ),

    # Agent Tool Misuse / Destructive Operations (MITRE AML.T0053)
    "destructive_tool_command": re.compile(
        r"(?i)(rm\s+-rf\s+/|drop\s+table\s+|delete\s+from\s+|format\s+c:|system_exec\(|chmod\s+777)"
    ),

    # Cryptographic Canary Token for Egress DLP (MITRE AML.T0057)
    "canary_token": re.compile(r"CANARY_TOKEN_SEC_[A-Z0-9]{4,12}|X42899_CES_NEKOT_YRANAC")
}


# ============================================================================
# CONTENT-PLANE SANITIZER & INTERCEPTOR
# ============================================================================

class ContentPlaneInterceptor:
    """
    Executes deep inspection and sanitization on payloads traversing the Content-Plane.
    """

    @classmethod
    def sanitize_input(cls, text: str) -> Tuple[bool, str, Optional[Dict[str, str]]]:
        """
        Scans inbound user prompts.
        Returns: (is_blocked: bool, sanitized_or_original_text: str, violation_metadata: Optional[dict])
        """
        # 1. Malicious URI scanning (SSRF / Metadata service targeting)
        if PATTERNS["malicious_uri"].search(text):
            return True, text, {
                "vector": "MALICIOUS_URI",
                "atlas_id": "AML.T0040",
                "owasp_id": "LLM05",
                "reason": "Forbidden URI scheme or metadata IP address detected in prompt."
            }

        # 2. Prompt Injection detection
        if PATTERNS["direct_injection"].search(text):
            return True, text, {
                "vector": "DIRECT_PROMPT_INJECTION",
                "atlas_id": "AML.T0051",
                "owasp_id": "LLM01",
                "reason": "Pattern matching system prompt override or instruction reset detected."
            }

        # 3. System prompt extraction probe
        if PATTERNS["system_prompt_extraction"].search(text):
            return True, text, {
                "vector": "SYSTEM_PROMPT_EXTRACTION",
                "atlas_id": "AML.T0058",
                "owasp_id": "LLM07",
                "reason": "System prompt probing or verbatim extraction attempt detected."
            }

        # 4. Destructive tool execution command injection
        if PATTERNS["destructive_tool_command"].search(text):
            return True, text, {
                "vector": "DESTRUCTIVE_TOOL_INVOCATION",
                "atlas_id": "AML.T0053",
                "owasp_id": "LLM06",
                "reason": "Unauthorized destructive shell/database mutation syntax detected."
            }

        # 5. Non-blocking Inbound PII Masking (Data Minimization)
        sanitized = text
        sanitized = PATTERNS["us_ssn"].sub("[REDACTED_SSN]", sanitized)
        sanitized = PATTERNS["credit_card"].sub("[REDACTED_CC]", sanitized)
        sanitized = PATTERNS["jwt_token"].sub("[REDACTED_JWT]", sanitized)
        sanitized = PATTERNS["generic_api_key"].sub("[REDACTED_SECRET]", sanitized)

        return False, sanitized, None

    @classmethod
    def sanitize_output(cls, text: str) -> Tuple[bool, str, Optional[Dict[str, str]]]:
        """
        Scans outbound model inference responses before release to client.
        Returns: (is_blocked: bool, sanitized_text: str, violation_metadata: Optional[dict])
        """
        # 1. Egress Canary Token Detection (Immediate blocking)
        if PATTERNS["canary_token"].search(text):
            return True, "[BLOCKED_BY_POLICY_GATEWAY] Egress leak prevented: Canary token detected.", {
                "vector": "DATA_EXFILTRATION_CANARY",
                "atlas_id": "AML.T0057",
                "owasp_id": "LLM02",
                "reason": "Outbound stream contained high-assurance diagnostic canary token."
            }

        # 2. Egress PII & Secret Redaction
        sanitized = text
        sanitized = PATTERNS["us_ssn"].sub("[REDACTED_SSN]", sanitized)
        sanitized = PATTERNS["credit_card"].sub("[REDACTED_CC]", sanitized)
        sanitized = PATTERNS["jwt_token"].sub("[REDACTED_JWT]", sanitized)

        # 3. Suppress unauthorized tool execution markers
        if "EXECUTE_TOOL:" in sanitized and ("rm -rf" in sanitized or "DROP TABLE" in sanitized):
            return True, "[BLOCKED_BY_POLICY_GATEWAY] Unauthorized destructive tool invocation suppressed.", {
                "vector": "TOOL_MISUSE_EGRESS",
                "atlas_id": "AML.T0053",
                "owasp_id": "LLM06",
                "reason": "Model emitted unauthorized tool command."
            }

        return False, sanitized, None


# ============================================================================
# CONTROL-PLANE POLICY ENGINE & TELEMETRY
# ============================================================================

class ControlPlanePolicyEngine:
    """
    Manages policy rules, evaluates risk blast radius, and logs immutable audit records.
    """

    @staticmethod
    def log_audit_event(
        request_id: str,
        action: str,
        latency_ms: float,
        violation: Optional[Dict[str, str]] = None
    ) -> None:
        event = {
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "request_id": request_id,
            "action": action,
            "latency_ms": round(latency_ms, 2),
            "violation": violation
        }
        # In production: Emits to Kafka, AWS CloudWatch, GCP Cloud Logging, or Azure Event Hubs
        if action == "BLOCK":
            logger.warning("AUDIT_VIOLATION: %s", json.dumps(event))
        else:
            logger.info("AUDIT_ALLOWED: %s", json.dumps(event))


# ============================================================================
# HTTP REQUEST HANDLER (OpenAI Compatible Endpoint)
# ============================================================================

class PolicyGatewayHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        """Health check and policy status endpoints."""
        if self.path in ["/healthz", "/health"]:
            self._send_json(200, {
                "status": "HEALTHY",
                "service": "triad-policy-as-code-gateway",
                "plane": "Content & Control Mesh",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            })
        elif self.path == "/policy/status":
            self._send_json(200, {
                "active_floor_settings": "FORTRESS_TIER",
                "enforcement_mode": "FAIL_CLOSED",
                "inspected_vectors": list(PATTERNS.keys())
            })
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        """Primary inference proxy endpoint (/v1/chat/completions)."""
        start_time = time.time()
        request_id = f"REQ-{uuid.uuid4().hex[:12].upper()}"

        if self.path != "/v1/chat/completions":
            self._send_json(404, {"error": "Endpoint not recognized. Use /v1/chat/completions"})
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._send_json(400, {"error": "Empty request body"})
            return

        body = self.rfile.read(content_length).decode("utf-8")
        try:
            req_data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Malformed JSON payload"})
            return

        messages: List[Dict[str, str]] = req_data.get("messages", [])
        if not messages:
            self._send_json(400, {"error": "messages array is required"})
            return

        latest_prompt = messages[-1].get("content", "")

        # --------------------------------------------------------------------
        # STAGE 1: Content-Plane Inbound Sanitization
        # --------------------------------------------------------------------
        is_blocked, sanitized_prompt, violation = ContentPlaneInterceptor.sanitize_input(latest_prompt)

        if is_blocked:
            latency_ms = (time.time() - start_time) * 1000
            ControlPlanePolicyEngine.log_audit_event(request_id, "BLOCK", latency_ms, violation)
            self._send_json(400, {
                "error": {
                    "code": "POLICY_VIOLATION",
                    "request_id": request_id,
                    "message": f"[BLOCKED_BY_POLICY_GATEWAY] {violation.get('reason')}",
                    "details": violation
                }
            })
            return

        # Replace prompt with sanitized representation
        messages[-1]["content"] = sanitized_prompt

        # --------------------------------------------------------------------
        # STAGE 2: Upstream Model Invocation (Simulated Inference Backend)
        # --------------------------------------------------------------------
        raw_model_response = self._invoke_upstream_model(messages)

        # --------------------------------------------------------------------
        # STAGE 3: Content-Plane Outbound Egress Sanitization
        # --------------------------------------------------------------------
        out_blocked, sanitized_output, out_violation = ContentPlaneInterceptor.sanitize_output(raw_model_response)

        latency_ms = (time.time() - start_time) * 1000

        if out_blocked:
            ControlPlanePolicyEngine.log_audit_event(request_id, "BLOCK", latency_ms, out_violation)
            self._send_json(400, {
                "error": {
                    "code": "EGRESS_POLICY_VIOLATION",
                    "request_id": request_id,
                    "message": sanitized_output,
                    "details": out_violation
                }
            })
            return

        # Success - Allow and log
        ControlPlanePolicyEngine.log_audit_event(request_id, "ALLOW", latency_ms, None)

        response_payload = {
            "id": f"chatcmpl-{request_id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req_data.get("model", "triad-governed-llm"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": sanitized_output
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": len(sanitized_prompt.split()),
                "completion_tokens": len(sanitized_output.split()),
                "total_tokens": len(sanitized_prompt.split()) + len(sanitized_output.split())
            },
            "governance_metadata": {
                "gateway_id": "TRIAD-MESH-01",
                "request_id": request_id,
                "sanitization_applied": sanitized_prompt != latest_prompt,
                "latency_eval_ms": round(latency_ms, 2)
            }
        }
        self._send_json(200, response_payload)

    def _invoke_upstream_model(self, messages: List[Dict[str, str]]) -> str:
        """
        In production: Calls upstream OpenAI/Vertex/Bedrock client.
        In standalone mode: Emits a standard governed completion.
        """
        last_msg = messages[-1].get("content", "")
        return f"Verified completion for request: '{last_msg[:60]}...'. All content-plane controls enforced."

    def _send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        response_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("X-Triad-Gateway-Version", "2.1.0")
        self.end_headers()
        self.wfile.write(response_bytes)

    def log_message(self, format, *args):
        # Suppress default stdout spew; custom logger handles audit events
        pass


def run_gateway(port: int = 8000) -> None:
    server_address = ("", port)
    # Enable SO_REUSEADDR
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(server_address, PolicyGatewayHandler) as httpd:
        logger.info("Triad Policy-as-Code Gateway listening on port %d...", port)
        logger.info("Endpoints: POST /v1/chat/completions | GET /healthz | GET /policy/status")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down gateway cleanly.")
            httpd.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_gateway(port=port_arg)
