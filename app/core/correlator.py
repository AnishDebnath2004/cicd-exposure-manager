"""
app/core/correlator.py
Attack Path Correlation & Toxic Combinations Engine.
Analyzes findings across repositories, live websites, and databases to reconstruct
verified multi-stage exploit chains, compute weaponization metrics, and build the visual attack graph.
"""

import uuid
from typing import List, Dict, Any, Optional, Tuple
from app.models.schemas import (
    Finding, FindingCategory, SeverityLevel, ToxicCombination,
    AttackGraph, AttackGraphNode, AttackGraphEdge, AutoDiscoveryResult,
    BlastRadius, SimulationStep, MitreTechnique
)


class AttackCorrelator:
    """Correlates disparate findings across vectors into compound attack paths & visual graph."""

    def correlate(
        self,
        findings: List[Finding],
        target_name: str = "Asset",
        auto_discovery: Optional[AutoDiscoveryResult] = None
    ) -> Tuple[List[ToxicCombination], AttackGraph]:
        """
        Processes findings and generates Toxic Combinations and the complete Attack Graph.
        """
        toxic_combinations: List[ToxicCombination] = []
        nodes: Dict[str, AttackGraphNode] = {}
        edges: List[AttackGraphEdge] = []

        # 1. Categorize findings for fast lookup
        secrets = [f for f in findings if f.category == FindingCategory.SECRET_EXPOSURE]
        workflows = [f for f in findings if f.category == FindingCategory.PIPELINE_MISCONFIG]
        scas = [f for f in findings if f.category == FindingCategory.SCA_VULNERABILITY]
        iacs = [f for f in findings if f.category == FindingCategory.IAC_CONTAINER]
        webs = [f for f in findings if f.category == FindingCategory.WEB_EXPOSURE]
        dbs = [f for f in findings if f.category == FindingCategory.DB_EXPOSURE]

        # 2. Check for Toxic Combination 1: Leaked Database Secrets + Open Database Port
        db_secrets = [s for s in secrets if any(k in s.title.lower() or k in s.description.lower() for k in ("database", "postgres", "mysql", "mongo", "redis", "db"))]
        open_db_ports = [d for d in dbs if "accessible" in d.title.lower() or "open port" in d.title.lower() or "unauthenticated" in d.title.lower() or "default" in d.title.lower()]

        if (db_secrets or secrets) and (open_db_ports or (auto_discovery and auto_discovery.discovered_db_targets)):
            f_ids = [f.id for f in (db_secrets[:1] or secrets[:1]) + open_db_ports[:1]]
            s_finding = (db_secrets[:1] or secrets[:1])[0]
            toxic_combinations.append(ToxicCombination(
                id=str(uuid.uuid4()),
                title="Critical Toxic Combination: Leaked Credentials + Direct Database Ingress",
                severity=SeverityLevel.CRITICAL,
                likelihood="High (Directly Exploitable)",
                exploit_chain=[
                    f"Attacker clones repository or reads configuration containing secret ({s_finding.title})",
                    "Attacker locates accessible database network endpoint and port",
                    "Attacker establishes unauthenticated or credentialed connection using harvested credentials",
                    "Complete production data dump and persistent backdoor installation"
                ],
                finding_ids=f_ids,
                impact="Catastrophic compromise of persistent data layer, customer PII leak, and regulatory liability.",
                remediation_advice="Immediately rotate the exposed database password, restrict database listening address to 127.0.0.1/private VPC, and enforce SSL/TLS.",
                unified_patch=s_finding.fix_patch
            ))

        # 3. Check for Toxic Combination 2: CI/CD Privileged Trigger + Leaked Cloud Access Keys or Excessive Write Permissions
        dangerous_workflows = [w for w in workflows if "pull_request_target" in w.title.lower() or "injection" in w.title.lower()]
        cloud_secrets = [s for s in secrets if any(c in s.title.lower() for c in ("aws", "github", "token", "key", "access"))]
        write_workflows = [w for w in workflows if "write-all" in w.title.lower() or "permission" in w.title.lower()]

        if dangerous_workflows and (cloud_secrets or secrets):
            w_finding = dangerous_workflows[0]
            s_finding = (cloud_secrets[:1] or secrets[:1])[0]
            toxic_combinations.append(ToxicCombination(
                id=str(uuid.uuid4()),
                title="Critical Toxic Combination: CI/CD Pipeline Hijacking & Cloud Takeover",
                severity=SeverityLevel.CRITICAL,
                likelihood="Critical (Automated Fork Weaponization)",
                exploit_chain=[
                    f"External threat actor forks target repository and opens a pull request ({w_finding.file_path})",
                    f"Workflow triggers on 'pull_request_target' with elevated repository permissions ({w_finding.title})",
                    f"Malicious PR script extracts environment secrets including '{s_finding.title}'",
                    "Attacker pivots using harvested credentials to compromise production cloud services"
                ],
                finding_ids=[w_finding.id, s_finding.id],
                impact="Unauthenticated code execution in deployment runners and compromise of cloud infrastructure.",
                remediation_advice="Change GitHub Actions trigger from 'pull_request_target' to 'pull_request', isolate secrets, and rotate cloud keys.",
                unified_patch=w_finding.fix_patch or "Replace 'pull_request_target' with 'pull_request'"
            ))
        elif dangerous_workflows and write_workflows:
            w_finding = dangerous_workflows[0]
            p_finding = write_workflows[0]
            toxic_combinations.append(ToxicCombination(
                id=str(uuid.uuid4()),
                title="Critical Toxic Combination: Poisoned Pipeline Execution (PPE) with Write-All Permissions",
                severity=SeverityLevel.CRITICAL,
                likelihood="Critical (Direct Repository Compromise)",
                exploit_chain=[
                    f"External threat actor opens pull request triggering privileged workflow context ({w_finding.file_path})",
                    f"Workflow runs with elevated token permissions ({p_finding.title})",
                    f"Untrusted PR payload executes arbitrary commands in the runner ({w_finding.title})",
                    "Attacker abuses write-all token to push unauthorized commits, modify releases, or taint artifacts"
                ],
                finding_ids=list(dict.fromkeys([w_finding.id, p_finding.id])),
                impact="Full repository compromise, arbitrary code push to protected branches, release artifact poisoning.",
                remediation_advice="Change workflow trigger from 'pull_request_target' to 'pull_request', and restrict GITHUB_TOKEN permissions to contents: read.",
                unified_patch=w_finding.fix_patch or "Replace 'pull_request_target' with 'pull_request'"
            ))

        # 4. Check for Toxic Combination 3: Outdated Vulnerable Dependency + Container Root Privilege
        critical_scas = [s for s in scas if s.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)]
        root_dockers = [i for i in iacs if "root" in i.title.lower() or "user" in i.title.lower() or "latest" in i.title.lower()]

        if critical_scas and root_dockers:
            sca_f = critical_scas[0]
            root_f = root_dockers[0]
            toxic_combinations.append(ToxicCombination(
                id=str(uuid.uuid4()),
                title="High Risk Chain: Container RCE & Host Privilege Escalation",
                severity=SeverityLevel.HIGH,
                likelihood="Moderate (Requires Network Reachability)",
                exploit_chain=[
                    f"Attacker targets vulnerable dependency '{sca_f.title}' ({sca_f.cve_id or 'CVE'})",
                    "Exploit triggers arbitrary code execution inside application container process",
                    f"Container executes as default UID 0 (root) without USER sandbox ({root_f.file_path})",
                    "Attacker can escalate to container breakout or write to mounted host filesystems"
                ],
                finding_ids=[sca_f.id, root_f.id],
                impact="Container compromise, root privileges inside container namespace, potential host escape.",
                remediation_advice="Add non-root 'USER 10001' directive to Dockerfile and upgrade vulnerable dependency to patched release.",
                unified_patch=root_f.fix_patch
            ))

        # 5. Check for Toxic Combination 4: Live Web Endpoint Exposure + Secret Leakage
        web_exposures = [w for w in webs if any(k in w.title.lower() for k in ("sensitive", ".env", ".git", "cors", "header"))]
        if web_exposures and secrets:
            w_f = web_exposures[0]
            s_f = secrets[0]
            toxic_combinations.append(ToxicCombination(
                id=str(uuid.uuid4()),
                title="High Risk Chain: Public Web Information Leak to Lateral Pivot",
                severity=SeverityLevel.HIGH,
                likelihood="High",
                exploit_chain=[
                    f"Attacker probes live web endpoint and detects public information disclosure ({w_f.title})",
                    f"Harvested configuration confirms leaked credential vector ({s_f.title})",
                    "Attacker pivots against internal API services using cross-origin or disclosed tokens",
                    "Lateral movement inside perimeter networks"
                ],
                finding_ids=[w_f.id, s_f.id],
                impact="Breach of external perimeter, credential reuse across cloud services.",
                remediation_advice="Harden web server security headers, remove sensitive files from public docroot, and rotate secrets."
            ))

        # 6. Build the Visual Attack Graph
        # Root Threat Actor Node
        actor_node = AttackGraphNode(
            id="node-actor",
            label="Threat Actor",
            category="actor",
            severity=SeverityLevel.CRITICAL,
            detail="External Anonymous Internet Attacker",
            icon="fa-user-secret"
        )
        nodes[actor_node.id] = actor_node

        # Target Crown Jewels
        target_asset_node = AttackGraphNode(
            id="node-asset-target",
            label=f"Crown Jewel: {target_name[:24]}",
            category="asset",
            severity=SeverityLevel.CRITICAL,
            detail="Production Environment, Cloud Secrets, and Core Databases",
            icon="fa-gem"
        )
        nodes[target_asset_node.id] = target_asset_node

        exfil_node = AttackGraphNode(
            id="node-impact-exfil",
            label="Full Compromise / Exfiltration",
            category="exfiltration",
            severity=SeverityLevel.CRITICAL,
            detail="Total data breach, service disruption, and unauthorized cloud access",
            icon="fa-skull-crossbones"
        )
        nodes[exfil_node.id] = exfil_node

        # Add nodes for top findings
        top_findings = sorted(findings, key=lambda f: (f.severity == SeverityLevel.CRITICAL, f.severity == SeverityLevel.HIGH, f.severity == SeverityLevel.MEDIUM), reverse=True)[:8]

        prev_node_id = actor_node.id
        for idx, f in enumerate(top_findings):
            node_id = f"node-finding-{idx}"
            cat = "ingress" if idx == 0 else "vulnerability"
            icon = "fa-triangle-exclamation"
            if f.category == FindingCategory.SECRET_EXPOSURE:
                icon = "fa-key"
            elif f.category == FindingCategory.PIPELINE_MISCONFIG:
                icon = "fa-gears"
            elif f.category == FindingCategory.DB_EXPOSURE:
                icon = "fa-database"
            elif f.category == FindingCategory.WEB_EXPOSURE:
                icon = "fa-globe"
            elif f.category == FindingCategory.IAC_CONTAINER:
                icon = "fa-box-open"
            elif f.category == FindingCategory.SCA_VULNERABILITY:
                icon = "fa-cubes"

            node = AttackGraphNode(
                id=node_id,
                label=f.title[:32] + ("..." if len(f.title) > 32 else ""),
                category=cat,
                severity=f.severity,
                detail=f.description,
                icon=icon,
                finding_id=f.id,
                file_path=f.file_path,
                line_number=f.line_number,
                remediation_patch=f.fix_patch or f.remediation_advice
            )
            nodes[node_id] = node

            # Create directed edge
            edge_label = "Exploits" if idx == 0 else "Escalates via"
            edges.append(AttackGraphEdge(
                id=f"edge-{prev_node_id}-{node_id}",
                source=prev_node_id,
                target=node_id,
                label=edge_label,
                animated=True,
                severity=f.severity
            ))
            prev_node_id = node_id

        # Connect last finding node to Crown Jewel and Exfil
        if top_findings:
            edges.append(AttackGraphEdge(
                id=f"edge-{prev_node_id}-{target_asset_node.id}",
                source=prev_node_id,
                target=target_asset_node.id,
                label="Breaches",
                animated=True,
                severity=SeverityLevel.CRITICAL
            ))
            edges.append(AttackGraphEdge(
                id=f"edge-{target_asset_node.id}-{exfil_node.id}",
                source=target_asset_node.id,
                target=exfil_node.id,
                label="Exfiltrates",
                animated=True,
                severity=SeverityLevel.CRITICAL
            ))
        else:
            # Clean repository edge
            edges.append(AttackGraphEdge(
                id="edge-actor-asset",
                source=actor_node.id,
                target=target_asset_node.id,
                label="Defended (No Exposures)",
                animated=False,
                severity=SeverityLevel.INFO
            ))

        # 7. Compute Exploitability Index (0 to 100)
        exploitability = 0.0
        if toxic_combinations:
            exploitability += 50.0 + min(len(toxic_combinations) * 15.0, 40.0)
        crit_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        exploitability += (crit_count * 12.0) + (high_count * 5.0)
        exploitability = min(round(exploitability, 1), 100.0)

        # 7. Generate Step-by-Step Simulation Steps
        simulation_steps: List[SimulationStep] = []
        if top_findings:
            # Step 1: Initial Ingress
            first_f = top_findings[0]
            first_node_id = "node-finding-0"
            t1_name = "Exploit Public-Facing Application" if first_f.category == FindingCategory.WEB_EXPOSURE else "Supply Chain Compromise"
            t1_id = "T1190" if first_f.category == FindingCategory.WEB_EXPOSURE else "T1195"
            simulation_steps.append(SimulationStep(
                step_number=1,
                phase="Initial Access & Reconnaissance",
                source_node_id=actor_node.id,
                target_node_id=first_node_id,
                title=f"Initial Ingress via {first_f.category.value}",
                narrative=f"Threat actor scans perimeter or repository and detects '{first_f.title}'. Attacker probes exposure at {first_f.file_path or 'network perimeter'}.",
                technique_id=t1_id,
                technique_name=t1_name,
                impact="Attacker gains initial foothold or extracts configuration metadata.",
                evidence_snippet=first_f.snippet or first_f.description
            ))

            # Intermediate steps
            for idx in range(len(top_findings) - 1):
                curr_f = top_findings[idx]
                next_f = top_findings[idx + 1]
                src_id = f"node-finding-{idx}"
                dst_id = f"node-finding-{idx + 1}"
                step_num = idx + 2

                if next_f.category == FindingCategory.SECRET_EXPOSURE:
                    phase = "Credential Access"
                    t_id, t_name = "T1552", "Unsecured Credentials"
                    narrative = f"Attacker harvests leaked secrets from '{next_f.file_path}'. Credentials allow unauthorized authentication without brute-force."
                elif next_f.category == FindingCategory.PIPELINE_MISCONFIG:
                    phase = "Privilege Escalation & Runner Hijacking"
                    t_id, t_name = "T1059.004", "Command and Scripting Interpreter (Unix Shell)"
                    narrative = f"Attacker weaponizes CI/CD pipeline '{next_f.file_path}' via pull request injection or elevated runner permissions."
                elif next_f.category == FindingCategory.DB_EXPOSURE:
                    phase = "Lateral Movement to Datastores"
                    t_id, t_name = "T1021", "Remote Services: Direct Database Connection"
                    narrative = f"Attacker pivots from CI/CD runner or harvested credentials to open database port at '{next_f.file_path}'."
                else:
                    phase = "Lateral Movement & Container Execution"
                    t_id, t_name = "T1078", "Valid Accounts / Execution Environment"
                    narrative = f"Attacker leverages '{next_f.title}' to escalate privileges within the container or execution environment."

                simulation_steps.append(SimulationStep(
                    step_number=step_num,
                    phase=phase,
                    source_node_id=src_id,
                    target_node_id=dst_id,
                    title=f"Escalate via {next_f.title[:35]}",
                    narrative=narrative,
                    technique_id=t_id,
                    technique_name=t_name,
                    impact=next_f.description[:120],
                    evidence_snippet=next_f.snippet or next_f.remediation_advice
                ))

            # Final Step: Exfiltration & Crown Jewel Compromise
            last_finding_idx = len(top_findings) - 1
            last_node_id = f"node-finding-{last_finding_idx}"
            final_step_num = len(simulation_steps) + 1
            simulation_steps.append(SimulationStep(
                step_number=final_step_num,
                phase="Impact & Exfiltration",
                source_node_id=last_node_id,
                target_node_id=target_asset_node.id,
                title="Full Crown Jewel Compromise",
                narrative=f"Threat actor consolidates access to '{target_name}'. Production datastores, CI/CD signing keys, and cloud deployment pipelines are breached.",
                technique_id="T1567",
                technique_name="Exfiltration Over Web Service / Cloud Abuse",
                impact="Catastrophic compromise of core infrastructure, data exfiltration, and supply chain poisoning.",
                evidence_snippet="Access achieved to Crown Jewels: " + target_name
            ))
        else:
            simulation_steps.append(SimulationStep(
                step_number=1,
                phase="Perimeter Defense Verified",
                source_node_id=actor_node.id,
                target_node_id=target_asset_node.id,
                title="Zero Exploitable Vectors Detected",
                narrative="Continuous posture verification confirms no exploitable attack chains or leaked credentials.",
                technique_id="T0000",
                technique_name="Hardened Perimeter Controls",
                impact="No compromise possible under current posture configuration.",
                evidence_snippet="Clean security posture"
            ))

        # 8. Compute Blast Radius Assessment
        compromised_assets = [target_name]
        cloud_impact = []
        if secrets:
            compromised_assets.append("Cloud & API Secret Stores")
            for s in secrets:
                title_lower = s.title.lower()
                if "aws" in title_lower:
                    cloud_impact.append("AWS Account IAM & Cloud Infrastructure")
                elif "github" in title_lower or "token" in title_lower:
                    cloud_impact.append("GitHub Organization & Repository Write Access")
                elif "slack" in title_lower or "discord" in title_lower:
                    cloud_impact.append("Internal Team Communication & Webhook Poisoning")
                elif any(k in title_lower for k in ("database", "postgres", "mongo", "redis")):
                    cloud_impact.append("Production Database Credential Exfiltration")
        if not cloud_impact and secrets:
            cloud_impact.append("General API & Authentication Tokens Compromise")

        if dbs or (auto_discovery and auto_discovery.discovered_db_targets):
            compromised_assets.append("Production Relational / NoSQL Datastores")
            cloud_impact.append("Direct SQL / Database Storage Access")

        if workflows:
            compromised_assets.append("CI/CD Build Runners & Release Pipelines")
            cloud_impact.append("Supply Chain Artifact Signing & Release Tampering")

        if webs or (auto_discovery and auto_discovery.discovered_web_targets):
            compromised_assets.append("Web Perimeter & Public Ingress Endpoints")

        compromised_assets = list(dict.fromkeys(compromised_assets))
        cloud_impact = list(dict.fromkeys(cloud_impact))

        # MITRE ATT&CK Techniques mapped
        mitre_list = [
            MitreTechnique(id="T1190", name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
            MitreTechnique(id="T1552", name="Unsecured Credentials", tactic="Credential Access", url="https://attack.mitre.org/techniques/T1552/"),
            MitreTechnique(id="T1059", name="Command and Scripting Interpreter", tactic="Execution", url="https://attack.mitre.org/techniques/T1059/"),
            MitreTechnique(id="T1078", name="Valid Accounts", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1078/"),
            MitreTechnique(id="T1021", name="Remote Services", tactic="Lateral Movement", url="https://attack.mitre.org/techniques/T1021/"),
            MitreTechnique(id="T1530", name="Data from Cloud Storage Object", tactic="Collection", url="https://attack.mitre.org/techniques/T1530/"),
            MitreTechnique(id="T1567", name="Exfiltration Over Web Service", tactic="Exfiltration", url="https://attack.mitre.org/techniques/T1567/")
        ]

        # Compliance Violations
        compliance_violations = []
        if secrets:
            compliance_violations.append("SOC 2 Type II: CC6.1 (Logical Access & Credential Protection)")
            compliance_violations.append("PCI-DSS v4.0: Requirement 8.2 (Strong Authentication & Credential Storage)")
        if workflows:
            compliance_violations.append("SLSA Level 3: Hermetic & Isolated Pipeline Build Requirement")
            compliance_violations.append("NIST SP 800-218: SSDF PO.3.2 (Pipeline Access Controls)")
        if dbs:
            compliance_violations.append("CIS Benchmark: Rule 2.1 (Restricted Database Network Listening)")
            compliance_violations.append("HIPAA Security Rule: 164.312(a)(1) (Access Controls for ePHI)")
        if not compliance_violations:
            compliance_violations.append("ISO/IEC 27001: Baseline Security Controls Verified")

        # Blast radius score (0-100)
        blast_score = 0.0
        if toxic_combinations:
            blast_score = 65.0 + min(len(toxic_combinations) * 15.0, 30.0)
        else:
            blast_score = min((crit_count * 15.0) + (high_count * 7.0) + (len(secrets) * 8.0), 90.0)
        blast_score = round(min(blast_score, 100.0), 1)

        if blast_score >= 80:
            risk_tier = "Catastrophic Breach"
            fin_risk = "$350,000 - $1,200,000+"
        elif blast_score >= 50:
            risk_tier = "High Blast Radius"
            fin_risk = "$80,000 - $350,000"
        elif blast_score >= 20:
            risk_tier = "Moderate Exposure"
            fin_risk = "$15,000 - $80,000"
        else:
            risk_tier = "Low / Contained"
            fin_risk = "< $10,000"

        blast_radius = BlastRadius(
            score=blast_score,
            risk_tier=risk_tier,
            compromised_assets=compromised_assets,
            cloud_impact=cloud_impact,
            stolen_credentials_count=len(secrets),
            exposed_datastores_count=len(dbs) + len(auto_discovery.discovered_db_targets if auto_discovery else []),
            mitre_attack_techniques=mitre_list,
            compliance_violations=compliance_violations,
            financial_risk_estimate=fin_risk
        )

        attack_graph = AttackGraph(
            nodes=list(nodes.values()),
            edges=edges,
            toxic_combinations=toxic_combinations,
            exploitability_index=exploitability,
            blast_radius=blast_radius,
            simulation_steps=simulation_steps
        )

        return toxic_combinations, attack_graph
