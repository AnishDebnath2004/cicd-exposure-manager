"""
app/core/copilot.py
Interactive Security Copilot Assistant.
Provides context-aware conversational insights regarding scan findings,
toxic combinations, attack paths, blast radius, and remediation advice.
"""

import os
import json
import re
from typing import Optional, List, Dict, Any
from app.models.schemas import ScanResult, CopilotChatResponse, SeverityLevel


class SecurityCopilot:
    """Answers user queries regarding security posture, findings, and attack surface."""

    @classmethod
    def chat(
        cls,
        message: str,
        scan: Optional[ScanResult] = None,
        finding_id: Optional[str] = None,
        history: Optional[List[Dict[str, str]]] = None
    ) -> CopilotChatResponse:
        """Processes user message in context of the active scan."""
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        openai_api_key = os.getenv("OPENAI_API_KEY")

        if gemini_api_key:
            try:
                return cls._chat_gemini(message, scan, finding_id, history, gemini_api_key)
            except Exception:
                pass

        if openai_api_key:
            try:
                return cls._chat_openai(message, scan, finding_id, history, openai_api_key)
            except Exception:
                pass

        return cls._chat_contextual(message, scan, finding_id)

    @classmethod
    def _chat_contextual(
        cls,
        message: str,
        scan: Optional[ScanResult] = None,
        finding_id: Optional[str] = None
    ) -> CopilotChatResponse:
        """Deterministic context-aware DevSecOps reasoning engine."""
        msg_lower = message.lower()
        suggested_actions = [
            "Explain our worst toxic combination",
            "What is our estimated blast radius?",
            "How do I fix the top vulnerability?",
            "Which findings violate SOC 2 CC6.1?"
        ]

        if not scan:
            return CopilotChatResponse(
                reply="I'm ShieldCI Security Copilot! Run or select an asset scan above, and I'll analyze your vulnerabilities, attack paths, and blast radius.",
                suggested_actions=["Run a new scan", "Check recent scan history"]
            )

        # 1. Finding specific question
        if finding_id:
            target_finding = next((f for f in scan.findings if f.id == finding_id), None)
            if target_finding:
                reply = (
                    f"### Finding Analysis: {target_finding.title}\n\n"
                    f"- **Severity:** `{target_finding.severity.value}`\n"
                    f"- **Location:** `{target_finding.file_path}`" + (f" (Line {target_finding.line_number})" if target_finding.line_number else "") + "\n"
                    f"- **Category:** {target_finding.category.value}\n\n"
                    f"**Why it's dangerous:**\n{target_finding.description}\n\n"
                    f"**Remediation Guidance:**\n{target_finding.remediation_advice}\n\n"
                    f"💡 *Tip: Click '✨ AI Fix & PR' on this finding to open an automated Pull Request on GitHub.*"
                )
                return CopilotChatResponse(
                    reply=reply,
                    suggested_actions=[
                        f"Show patch for {target_finding.title[:20]}",
                        "Is this part of a toxic combination?",
                        "What is the blast radius?"
                    ]
                )

        # 2. Blast radius question
        if any(k in msg_lower for k in ("blast radius", "blast", "impact", "radius", "compromise")):
            br = scan.attack_graph.blast_radius if scan.attack_graph else None
            if br:
                assets_str = "\n".join(f"- 🎯 {a}" for a in br.compromised_assets)
                cloud_str = "\n".join(f"- ☁️ {c}" for c in br.cloud_impact)
                reply = (
                    f"### 💥 Blast Radius Assessment: **{br.score}% ({br.risk_tier.upper()})**\n\n"
                    f"If an adversary exploits your current posture vulnerabilities, the breach impact is estimated at **{br.financial_risk_estimate}**.\n\n"
                    f"**Potentially Compromised Assets:**\n{assets_str}\n\n"
                    f"**Cloud & Infrastructure Vectors at Risk:**\n{cloud_str or '- None identified'}\n\n"
                    f"- **Leaked Credentials:** {br.stolen_credentials_count}\n"
                    f"- **Exposed Datastores:** {br.exposed_datastores_count}\n\n"
                    f"**Key Violations:**\n" + "\n".join(f"- ⚖️ {v}" for v in br.compliance_violations[:3])
                )
            else:
                reply = "Blast radius assessment is minimal. Your attack surface shows no critical multi-vector toxic combinations."
            return CopilotChatResponse(reply=reply, suggested_actions=["Simulate exploit trajectory", "How do I lower our score?"])

        # 3. Toxic combination question
        if any(k in msg_lower for k in ("toxic", "combo", "chain", "exploit chain")):
            if scan.toxic_combinations:
                tc = scan.toxic_combinations[0]
                steps = "\n".join(f"{i+1}. {step}" for i, step in enumerate(tc.exploit_chain))
                reply = (
                    f"### ⚠️ Toxic Combination: {tc.title}\n\n"
                    f"**Severity:** `{tc.severity.value}` | **Likelihood:** {tc.likelihood}\n\n"
                    f"**Exploit Chain Trajectory:**\n{steps}\n\n"
                    f"**Impact:**\n{tc.impact}\n\n"
                    f"**Recommended Fix:**\n{tc.remediation_advice}"
                )
            else:
                reply = "✅ Great news! No compound Toxic Combinations were identified in this scan. Disparate findings do not currently link into weaponizable chains."
            return CopilotChatResponse(reply=reply, suggested_actions=["Explain simulation steps", "Show all critical findings"])

        # 4. Simulation question
        if any(k in msg_lower for k in ("simulation", "simulate", "kill chain", "steps")):
            steps = scan.attack_graph.simulation_steps if scan.attack_graph else []
            if steps:
                step_str = "\n".join(f"**Step {s.step_number} ({s.phase}):** {s.title} — *{s.narrative}*" for s in steps)
                reply = (
                    f"### 🎯 Attack Simulation Trajectory\n\n"
                    f"Here is how a threat actor would progress through your architecture:\n\n{step_str}\n\n"
                    f"You can watch this play in real time on the **Attack Graph tab** using the Simulation controls."
                )
            else:
                reply = "No active exploit simulation steps available for this asset."
            return CopilotChatResponse(reply=reply, suggested_actions=["Play simulation", "What is our blast radius?"])

        # 5. Fix / Remediation question
        if any(k in msg_lower for k in ("fix", "remediate", "patch", "repair")):
            crit_findings = [f for f in scan.findings if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)]
            if crit_findings:
                top = crit_findings[0]
                reply = (
                    f"### Recommended Priority Fix: {top.title}\n\n"
                    f"**File:** `{top.file_path}`\n\n"
                    f"**Action:** {top.remediation_advice}\n\n"
                    f"Use the **✨ AI Fix & PR** button in the findings view to generate an automated pull request with syntactically valid patches."
                )
            else:
                reply = "All high/critical findings have been resolved! Check medium/low findings or compliance scorecards."
            return CopilotChatResponse(reply=reply, suggested_actions=["Check compliance status", "Download full patch"])

        # 6. Compliance question
        if any(k in msg_lower for k in ("compliance", "soc", "soc 2", "pci", "iso", "slsa")):
            br = scan.attack_graph.blast_radius if scan.attack_graph else None
            viols = br.compliance_violations if br else []
            reply = (
                f"### 📜 Compliance & Regulatory Posture\n\n"
                f"Based on our static and perimeter analysis of **{scan.repo_name}**:\n\n" +
                ("\n".join(f"- 🔴 {v}" for v in viols) if viols else "- 🟢 No direct compliance control violations detected.") +
                f"\n\n*Pipeline Exposure Score (PES):* **{scan.summary.pipeline_exposure_score}/100 ({scan.summary.risk_grade})**"
            )
            return CopilotChatResponse(reply=reply, suggested_actions=["How do we pass SOC 2 CC6.1?", "Fix leaked secrets"])

        # Default overview
        reply = (
            f"**ShieldCI Posture Summary for `{scan.repo_name}`**:\n\n"
            f"- **Exposure Score (PES):** {scan.summary.pipeline_exposure_score}/100 ({scan.summary.risk_grade})\n"
            f"- **Policy Gate:** {'PASSED ✅' if scan.summary.policy_passed else 'BLOCKED ❌'}\n"
            f"- **Total Findings:** {scan.summary.total_findings} ({scan.summary.critical_count} Critical, {scan.summary.high_count} High)\n"
            f"- **Toxic Combinations:** {len(scan.toxic_combinations)}\n\n"
            f"Ask me about any specific finding, how to fix an issue, or how to simulate an attack path!"
        )
        return CopilotChatResponse(reply=reply, suggested_actions=suggested_actions)

    @classmethod
    def _chat_gemini(cls, message: str, scan: Optional[ScanResult], finding_id: Optional[str], history: Optional[List[Dict[str, str]]], api_key: str) -> CopilotChatResponse:
        import requests
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
        context = ""
        if scan:
            context = f"""
Asset: {scan.repo_name}
PES Score: {scan.summary.pipeline_exposure_score}/100 (Grade {scan.summary.risk_grade})
Total Findings: {scan.summary.total_findings} (Critical: {scan.summary.critical_count}, High: {scan.summary.high_count})
Toxic Combos: {len(scan.toxic_combinations)}
Sample Findings: {[{'title': f.title, 'path': f.file_path, 'sev': f.severity.value} for f in scan.findings[:5]]}
"""
        prompt = f"System: You are ShieldCI Security Copilot, an elite DevSecOps and AppSec AI assistant. Context:\n{context}\nUser Question: {message}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        res = requests.post(url, json=payload, timeout=12)
        res.raise_for_status()
        text = res.json()["candidates"][0]["content"]["parts"][0]["text"]
        return CopilotChatResponse(
            reply=text,
            suggested_actions=["What is our blast radius?", "How to fix top finding?", "Simulate attack chain"]
        )

    @classmethod
    def _chat_openai(cls, message: str, scan: Optional[ScanResult], finding_id: Optional[str], history: Optional[List[Dict[str, str]]], api_key: str) -> CopilotChatResponse:
        import requests
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        context = f"Asset: {scan.repo_name}, PES: {scan.summary.pipeline_exposure_score}" if scan else ""
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": f"You are ShieldCI Security Copilot. Context: {context}"},
                {"role": "user", "content": message}
            ]
        }
        res = requests.post(url, json=payload, headers=headers, timeout=12)
        res.raise_for_status()
        text = res.json()["choices"][0]["message"]["content"]
        return CopilotChatResponse(
            reply=text,
            suggested_actions=["What is our blast radius?", "How to fix top finding?"]
        )
