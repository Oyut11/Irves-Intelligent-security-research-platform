"""
IRVES — Cross-Phase Correlation Service
Phase E: Correlates findings across Static, Dynamic, and Network analysis phases.

Responsibilities:
- Correlate static findings with dynamic runtime evidence
- Build attack chains from entry to impact
- Confirm/Invalidate findings with multi-phase evidence
- Generate correlation confidence scores
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
import re

from database.models import Finding, FindingSeverity

logger = logging.getLogger(__name__)


class CorrelationType(str, Enum):
    """Types of correlation between findings."""
    STATIC_TO_DYNAMIC = "static_to_dynamic"      # Code finding confirmed at runtime
    DYNAMIC_TO_NETWORK = "dynamic_to_network"    # Runtime behavior seen in traffic
    STATIC_TO_NETWORK = "static_to_network"      # Code issue manifested in traffic
    CHAIN = "chain"                               # Part of multi-step attack
    DUPLICATE = "duplicate"                       # Same issue found by different tools


class CorrelationConfidence(str, Enum):
    """Confidence level in correlation."""
    HIGH = "high"      # Direct evidence match
    MEDIUM = "medium"  # Strong indirect evidence
    LOW = "low"        # Weak/potential correlation


@dataclass
class CorrelatedFinding:
    """
    Represents a finding enriched with correlation data.

    Links findings across analysis phases and provides
    attack chain context.
    """
    finding_id: str
    title: str
    severity: str
    phase: str  # static, dynamic, network, exploit
    category: str

    # Correlation data
    correlated_with: List[str] = field(default_factory=list)  # Finding IDs
    correlation_type: Optional[CorrelationType] = None
    confidence: CorrelationConfidence = CorrelationConfidence.LOW

    # Attack chain context
    attack_chain_position: Optional[int] = None  # 1=entry, 2=pivot, 3=target
    attack_chain_id: Optional[str] = None

    # Evidence summary
    static_evidence: Optional[str] = None
    dynamic_evidence: Optional[str] = None
    network_evidence: Optional[str] = None

    # Status
    is_confirmed: bool = False  # Confirmed by multiple phases
    is_false_positive: bool = False
    notes: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "phase": self.phase,
            "category": self.category,
            "correlated_with": self.correlated_with,
            "correlation_type": self.correlation_type.value if self.correlation_type else None,
            "confidence": self.confidence.value,
            "attack_chain_position": self.attack_chain_position,
            "attack_chain_id": self.attack_chain_id,
            "evidence_summary": {
                "static": self.static_evidence,
                "dynamic": self.dynamic_evidence,
                "network": self.network_evidence,
            },
            "is_confirmed": self.is_confirmed,
            "is_false_positive": self.is_false_positive,
            "notes": self.notes,
        }


@dataclass
class AttackChain:
    """
    Represents a multi-step attack path through findings.

    Shows how vulnerabilities chain together from entry point
    to ultimate impact.
    """
    chain_id: str
    name: str
    description: str

    # Steps in the chain (ordered)
    steps: List[CorrelatedFinding] = field(default_factory=list)

    # Entry and exit points
    entry_point: Optional[str] = None
    target_asset: Optional[str] = None

    # Risk assessment
    overall_risk: str = "medium"
    likelihood: float = 0.5  # 0.0-1.0
    impact: str = "medium"

    # Prerequisites for attack
    prerequisites: List[str] = field(default_factory=list)

    # Mitigations
    mitigations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
            "entry_point": self.entry_point,
            "target_asset": self.target_asset,
            "overall_risk": self.overall_risk,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "prerequisites": self.prerequisites,
            "mitigations": self.mitigations,
        }


class FindingCorrelator:
    """
    Correlates findings across analysis phases.

    Uses multiple strategies:
    1. Location matching (file/method names)
    2. Evidence text similarity
    3. Category/OWASP mapping alignment
    4. Temporal proximity (findings close in time)
    """

    def __init__(self):
        self.correlations: List[Tuple[str, str, CorrelationType, CorrelationConfidence]] = []
        self.attack_chains: List[AttackChain] = []

    def correlate_findings(
        self,
        static_findings: List[Finding],
        dynamic_findings: List[Finding],
        network_findings: List[Finding],
    ) -> Dict[str, List[CorrelatedFinding]]:
        """
        Main correlation method.

        Args:
            static_findings: From code analysis (apk_analyzer, Semgrep, etc.)
            dynamic_findings: From runtime analysis (Frida, etc.)
            network_findings: From traffic analysis (mitmproxy, etc.)

        Returns:
            Dict with correlated findings by phase
        """
        logger.info(f"[Correlator] Starting correlation: {len(static_findings)} static, "
                   f"{len(dynamic_findings)} dynamic, {len(network_findings)} network")

        # Convert to CorrelatedFinding objects
        correlated_static = [self._to_correlated(f, "static") for f in static_findings]
        correlated_dynamic = [self._to_correlated(f, "dynamic") for f in dynamic_findings]
        correlated_network = [self._to_correlated(f, "network") for f in network_findings]

        # Run correlation algorithms
        self._correlate_static_to_dynamic(correlated_static, correlated_dynamic)
        self._correlate_dynamic_to_network(correlated_dynamic, correlated_network)
        self._correlate_static_to_network(correlated_static, correlated_network)
        self._find_duplicates(correlated_static + correlated_dynamic + correlated_network)

        # Build attack chains
        self._build_attack_chains(correlated_static, correlated_dynamic, correlated_network)

        # Mark confirmed findings (found in multiple phases)
        self._mark_confirmed_findings(correlated_static, correlated_dynamic, correlated_network)

        logger.info(f"[Correlator] Complete: {len(self.correlations)} correlations, "
                   f"{len(self.attack_chains)} attack chains")

        return {
            "static": [f.to_dict() for f in correlated_static],
            "dynamic": [f.to_dict() for f in correlated_dynamic],
            "network": [f.to_dict() for f in correlated_network],
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "correlation_summary": {
                "total_correlations": len(self.correlations),
                "high_confidence": len([c for c in self.correlations if c[3] == CorrelationConfidence.HIGH]),
                "medium_confidence": len([c for c in self.correlations if c[3] == CorrelationConfidence.MEDIUM]),
                "attack_chains_found": len(self.attack_chains),
            }
        }

    def _to_correlated(self, finding: Finding, phase: str) -> CorrelatedFinding:
        """Convert a Finding to CorrelatedFinding."""
        return CorrelatedFinding(
            finding_id=finding.id,
            title=finding.title,
            severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            phase=phase,
            category=finding.category or finding.owasp_mapping or "Uncategorized",
            static_evidence=finding.code_snippet if phase == "static" else None,
            dynamic_evidence=finding.description if phase == "dynamic" else None,
            network_evidence=finding.location if phase == "network" else None,
        )

    def _correlate_static_to_dynamic(
        self,
        static: List[CorrelatedFinding],
        dynamic: List[CorrelatedFinding],
    ) -> None:
        """
        Correlate static code findings with runtime evidence.

        Example: Hardcoded key in code + Key extracted at runtime = HIGH confidence
        """
        for s in static:
            for d in dynamic:
                confidence = self._calculate_correlation_confidence(s, d)

                if confidence:
                    s.correlated_with.append(d.finding_id)
                    d.correlated_with.append(s.finding_id)
                    s.correlation_type = CorrelationType.STATIC_TO_DYNAMIC
                    d.correlation_type = CorrelationType.STATIC_TO_DYNAMIC
                    s.confidence = confidence
                    d.confidence = confidence

                    # Merge evidence
                    d.static_evidence = s.static_evidence
                    s.dynamic_evidence = d.dynamic_evidence

                    self.correlations.append((s.finding_id, d.finding_id,
                                            CorrelationType.STATIC_TO_DYNAMIC, confidence))

    def _correlate_dynamic_to_network(
        self,
        dynamic: List[CorrelatedFinding],
        network: List[CorrelatedFinding],
    ) -> None:
        """
        Correlate runtime behavior with network traffic.

        Example: SSL bypass hook + Unencrypted traffic observed = HIGH confidence
        """
        for d in dynamic:
            for n in network:
                confidence = self._calculate_correlation_confidence(d, n)

                if confidence:
                    d.correlated_with.append(n.finding_id)
                    n.correlated_with.append(d.finding_id)
                    d.correlation_type = CorrelationType.DYNAMIC_TO_NETWORK
                    n.correlation_type = CorrelationType.DYNAMIC_TO_NETWORK
                    d.confidence = confidence
                    n.confidence = confidence

                    # Merge evidence
                    n.dynamic_evidence = d.dynamic_evidence
                    d.network_evidence = n.network_evidence

                    self.correlations.append((d.finding_id, n.finding_id,
                                            CorrelationType.DYNAMIC_TO_NETWORK, confidence))

    def _correlate_static_to_network(
        self,
        static: List[CorrelatedFinding],
        network: List[CorrelatedFinding],
    ) -> None:
        """
        Correlate code issues with network manifestations.

        Example: Insecure HTTP in code + HTTP traffic observed = MEDIUM confidence
        """
        for s in static:
            for n in network:
                # Skip if already correlated through dynamic
                if n.finding_id in s.correlated_with:
                    continue

                confidence = self._calculate_correlation_confidence(s, n)

                if confidence:
                    s.correlated_with.append(n.finding_id)
                    n.correlated_with.append(s.finding_id)
                    s.correlation_type = CorrelationType.STATIC_TO_NETWORK
                    n.correlation_type = CorrelationType.STATIC_TO_NETWORK
                    s.confidence = confidence
                    n.confidence = confidence

                    self.correlations.append((s.finding_id, n.finding_id,
                                            CorrelationType.STATIC_TO_NETWORK, confidence))

    def _find_duplicates(self, all_findings: List[CorrelatedFinding]) -> None:
        """Find duplicate findings from different tools."""
        for i, f1 in enumerate(all_findings):
            for f2 in all_findings[i+1:]:
                if f1.finding_id == f2.finding_id:
                    continue

                # Check for duplicates (same title, similar location)
                if self._is_duplicate(f1, f2):
                    f1.correlated_with.append(f2.finding_id)
                    f2.correlated_with.append(f1.finding_id)
                    self.correlations.append((f1.finding_id, f2.finding_id,
                                            CorrelationType.DUPLICATE, CorrelationConfidence.HIGH))

    def _is_duplicate(self, f1: CorrelatedFinding, f2: CorrelatedFinding) -> bool:
        """Check if two findings are duplicates."""
        # Same title (or very similar)
        title_similarity = self._text_similarity(f1.title.lower(), f2.title.lower())
        if title_similarity > 0.8:
            return True

        # Same category + similar location
        if f1.category == f2.category:
            loc_sim = self._text_similarity(
                (f1.static_evidence or "").lower(),
                (f2.static_evidence or "").lower()
            )
            if loc_sim > 0.7:
                return True

        return False

    def _calculate_correlation_confidence(
        self,
        f1: CorrelatedFinding,
        f2: CorrelatedFinding,
    ) -> Optional[CorrelationConfidence]:
        """
        Calculate confidence level for correlation.

        Returns None if no correlation, otherwise confidence level.
        """
        score = 0.0

        # 1. Category alignment (same OWASP category)
        if f1.category and f2.category:
            if f1.category == f2.category:
                score += 0.3
            elif self._category_related(f1.category, f2.category):
                score += 0.15

        # 2. Text similarity in evidence
        texts = []
        if f1.static_evidence and f2.static_evidence:
            texts.append((f1.static_evidence, f2.static_evidence))
        if f1.dynamic_evidence and f2.dynamic_evidence:
            texts.append((f1.dynamic_evidence, f2.dynamic_evidence))
        if f1.network_evidence and f2.network_evidence:
            texts.append((f1.network_evidence, f2.network_evidence))

        for t1, t2 in texts:
            sim = self._text_similarity(t1.lower(), t2.lower())
            score += sim * 0.4

        # 3. Keyword matching
        keywords1 = self._extract_keywords(f1.title + " " + str(f1.static_evidence))
        keywords2 = self._extract_keywords(f2.title + " " + str(f2.static_evidence))
        common = keywords1 & keywords2
        if common:
            score += len(common) * 0.1

        # Map score to confidence
        if score >= 0.7:
            return CorrelationConfidence.HIGH
        elif score >= 0.4:
            return CorrelationConfidence.MEDIUM
        elif score >= 0.2:
            return CorrelationConfidence.LOW

        return None

    def _build_attack_chains(
        self,
        static: List[CorrelatedFinding],
        dynamic: List[CorrelatedFinding],
        network: List[CorrelatedFinding],
    ) -> None:
        """
        Build attack chains from correlated findings.

        Chains progress: Entry Point → Pivot/Exploit → Target
        """
        all_findings = static + dynamic + network

        # Find high-confidence correlations to build chains
        high_conf = [c for c in self.correlations if c[3] in (CorrelationConfidence.HIGH, CorrelationConfidence.MEDIUM)]

        if len(high_conf) < 2:
            return  # Need at least 2 correlations for a chain

        # Build chains by following correlations
        chains_built = 0
        for seed in all_findings:
            if seed.confidence != CorrelationConfidence.HIGH:
                continue

            chain = self._build_chain_from_seed(seed, all_findings)
            if len(chain.steps) >= 2:
                self.attack_chains.append(chain)
                chains_built += 1

                # Mark findings with chain position
                for i, step in enumerate(chain.steps):
                    step.attack_chain_id = chain.chain_id
                    step.attack_chain_position = i + 1

        logger.info(f"[Correlator] Built {chains_built} attack chains")

    def _build_chain_from_seed(
        self,
        seed: CorrelatedFinding,
        all_findings: List[CorrelatedFinding],
    ) -> AttackChain:
        """Build an attack chain starting from a seed finding."""
        chain_id = f"chain_{seed.finding_id}_{datetime.utcnow().timestamp():.0f}"

        # Find related findings
        chain_findings = [seed]
        visited = {seed.finding_id}

        # BFS to find connected findings
        to_visit = list(seed.correlated_with)
        while to_visit and len(chain_findings) < 5:  # Max 5 steps
            fid = to_visit.pop(0)
            if fid in visited:
                continue

            finding = next((f for f in all_findings if f.finding_id == fid), None)
            if finding:
                chain_findings.append(finding)
                visited.add(fid)
                to_visit.extend([c for c in finding.correlated_with if c not in visited])

        # Determine chain metadata
        entry = chain_findings[0]
        target = chain_findings[-1]

        return AttackChain(
            chain_id=chain_id,
            name=f"Attack via {entry.title[:40]}",
            description=f"Multi-step attack from {entry.phase} to {target.phase}",
            steps=chain_findings,
            entry_point=entry.title,
            target_asset=target.title,
            overall_risk=target.severity if target.severity in ("critical", "high") else "medium",
            likelihood=0.7 if entry.confidence == CorrelationConfidence.HIGH else 0.5,
        )

    def _mark_confirmed_findings(
        self,
        static: List[CorrelatedFinding],
        dynamic: List[CorrelatedFinding],
        network: List[CorrelatedFinding],
    ) -> None:
        """Mark findings as confirmed if found in multiple phases."""
        all_findings = static + dynamic + network

        for f in all_findings:
            # A finding is confirmed if it has correlations with different phases
            correlated_phases = set()
            for fid in f.correlated_with:
                related = next((r for r in all_findings if r.finding_id == fid), None)
                if related:
                    correlated_phases.add(related.phase)

            # Confirmed if found in 2+ phases
            phases_present = {f.phase} | correlated_phases
            if len(phases_present) >= 2:
                f.is_confirmed = True

    def _text_similarity(self, s1: str, s2: str) -> float:
        """Calculate simple text similarity (0.0-1.0)."""
        if not s1 or not s2:
            return 0.0

        # Simple word overlap
        words1 = set(s1.split())
        words2 = set(s2.split())

        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2

        return len(intersection) / len(union) if union else 0.0

    def _extract_keywords(self, text: str) -> Set[str]:
        """Extract security-relevant keywords."""
        if not text:
            return set()

        # Security keywords
        keywords = {
            "key", "password", "secret", "token", "credential",
            "crypto", "encrypt", "ssl", "tls", "certificate",
            "sql", "injection", "xss", "auth", "session",
            "permission", "root", "admin", "bypass",
            "http", "https", "network", "api", "request",
        }

        found = set()
        text_lower = text.lower()
        for kw in keywords:
            if kw in text_lower:
                found.add(kw)

        return found

    def _category_related(self, c1: str, c2: str) -> bool:
        """Check if two OWASP categories are related."""
        # Simple check: same main category (e.g., M1, M2)
        m1 = c1.split(":")[0] if ":" in c1 else c1[:2]
        m2 = c2.split(":")[0] if ":" in c2 else c2[:2]
        return m1 == m2


# Global instance
correlator = FindingCorrelator()
