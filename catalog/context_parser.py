"""
catalog/context_parser.py
─────────────────────────
Parses a free-text business context file into a structured JSON
using Claude.
"""

import json
try:
    import anthropic
except ImportError:
    anthropic = None

from shared.logger import audit_log

DEFAULT_CTX = {
    "custom_sinks": [],
    "custom_sources": [],
    "sensitive_flows": [],
    "non_http_sources": [],
    "business_notes": ""
}

def parse_business_context(context_text: str, run_id: str = "local") -> dict:
    """Parses free-text context into a structured dictionary."""
    if not context_text or not context_text.strip():
        return DEFAULT_CTX.copy()

    if not anthropic:
        # Fallback if no LLM: just stuff into business_notes
        ctx = DEFAULT_CTX.copy()
        ctx["business_notes"] = context_text
        return ctx

    client = anthropic.Anthropic()
    
    prompt = f"""You are an expert security analyst. You have been given the following business context text about an application:

<context>
{context_text}
</context>

Extract and structure this information into the following JSON schema:
{{
  "custom_sinks": [
    {{
      "name": "method_name",
      "class": "ClassName",
      "vuln_type": "vuln classification (e.g. sqli, rce, xss)",
      "confidence": "HIGH|MED|LOW",
      "note": "brief explanation"
    }}
  ],
  "custom_sources": [
    {{
      "name": "method_name",
      "class": "ClassName",
      "source_type": "type (e.g. queue, websocket)",
      "note": "brief explanation"
    }}
  ],
  "sensitive_flows": [
    {{
      "description": "brief description",
      "entry": "route or controller name",
      "risk": "risk description"
    }}
  ],
  "non_http_sources": [
    "ClassName::methodName"
  ],
  "business_notes": "any other raw relevant context, especially about auth bypasses, roles, etc."
}}

Return ONLY the raw JSON object, without any markdown formatting wrappers or explanations. Keep the arrays empty if you can't find matching data.
"""

    try:
        response = client.messages.create(
            model="claude-3-5-sonnet-latest",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )
        content = response.content[0].text
        start = content.find('{')
        end = content.rfind('}')
        if start != -1 and end != -1:
            parsed = json.loads(content[start:end+1])
            audit_log("reports/" + run_id, run_id, "context_parser:success", {
                "sinks": len(parsed.get("custom_sinks", [])),
                "flows": len(parsed.get("sensitive_flows", []))
            })
            return parsed
    except Exception as e:
        audit_log("reports/" + run_id, run_id, "context_parser:error", {"error": str(e)})

    # Fallback in case of parse error
    ctx = DEFAULT_CTX.copy()
    ctx["business_notes"] = context_text
    return ctx
