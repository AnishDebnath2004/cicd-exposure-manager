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
    AttackGraph, AttackGraphNode, AttackGraphEdge, AutoDiscoveryResult
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

        # 3. Check for Toxic Combination 2: CI/CD Privileged Trigger + Leaked Cloud Access Keys
        dangerous_workflows = [w for w in workflows if "pull_request_target" in w.title.lower() or "injection" in w.title.lower()]
        cloud_secrets = [s for s in secrets if any(c in s.title.lower() for c in ("aws", "github", "token", "key", "access"))]

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

        attack_graph = AttackGraph(
            nodes=list(nodes.values()),
            edges=edges,
            toxic_combinations=toxic_combinations,
            exploitability_index=exploitability
        )

        return toxic_combinations, attack_graph
