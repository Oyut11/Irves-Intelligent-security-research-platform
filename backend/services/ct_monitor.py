"""
IRVES — Certificate Transparency (CT) Monitor
Monitors Certificate Transparency logs for domains from intercepted traffic.
Detects subdomain enumeration opportunities and potential subdomain takeover risks.
"""

import asyncio
import logging
import re
import socket
import ssl
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class DomainInfo:
    """Information about a domain gathered from CT and certificate analysis."""
    domain: str
    subdomains: Set[str] = field(default_factory=set)
    has_ct_logs: bool = False
    certificate_issuers: List[str] = field(default_factory=list)
    san_entries: List[str] = field(default_factory=list)
    subdomain_takeover_risks: List[dict] = field(default_factory=list)
    last_analyzed: Optional[datetime] = None


class CertificateTransparencyMonitor:
    """Monitor Certificate Transparency for domains in captured traffic."""
    
    # Cloud services vulnerable to subdomain takeover
    TAKEOVER_TARGETS = {
        "github.io": {"service": "GitHub Pages", "vulnerability": "CNAME to non-existent repo"},
        "herokuapp.com": {"service": "Heroku", "vulnerability": "CNAME to non-existent app"},
        "azurewebsites.net": {"service": "Azure App Service", "vulnerability": "CNAME to deleted app"},
        "cloudapp.net": {"service": "Azure Cloud Services", "vulnerability": "CNAME to deleted service"},
        "amazonaws.com": {"service": "AWS", "vulnerability": "CNAME to deleted S3 bucket or EC2"},
        "s3.amazonaws.com": {"service": "AWS S3", "vulnerability": "CNAME to non-existent bucket"},
        "firebaseapp.com": {"service": "Firebase", "vulnerability": "CNAME to deleted project"},
        "ghost.io": {"service": "Ghost", "vulnerability": "CNAME to deleted blog"},
        "wordpress.com": {"service": "WordPress.com", "vulnerability": "CNAME to deleted site"},
        "surge.sh": {"service": "Surge.sh", "vulnerability": "CNAME to non-existent project"},
        "netlify.app": {"service": "Netlify", "vulnerability": "CNAME to deleted site"},
        "vercel.app": {"service": "Vercel", "vulnerability": "CNAME to deleted deployment"},
    }
    
    def __init__(self):
        self._cache: Dict[str, DomainInfo] = {}
        self._cache_ttl = timedelta(hours=24)
    
    async def analyze_domain(self, domain: str) -> DomainInfo:
        """Analyze a domain for CT information and takeover risks."""
        # Check cache first
        if domain in self._cache:
            cached = self._cache[domain]
            if cached.last_analyzed and datetime.now() - cached.last_analyzed < self._cache_ttl:
                return cached
        
        info = DomainInfo(domain=domain)
        
        try:
            # Get certificate info via SSL
            cert_info = await self._get_certificate_info(domain)
            if cert_info:
                info.certificate_issuers = cert_info.get("issuers", [])
                info.san_entries = cert_info.get("san", [])
                info.subdomains.update(cert_info.get("san", []))
                info.has_ct_logs = len(info.san_entries) > 0
            
            # Check for takeover risks
            info.subdomain_takeover_risks = await self._check_takeover_risks(domain, info.subdomains)
            
            info.last_analyzed = datetime.now()
            self._cache[domain] = info
            
        except Exception as e:
            logger.warning(f"CT analysis failed for {domain}: {e}")
        
        return info
    
    async def _get_certificate_info(self, domain: str) -> Optional[dict]:
        """Get certificate information via SSL connection."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try to connect and get certificate
            loop = asyncio.get_event_loop()
            
            def get_cert():
                try:
                    with socket.create_connection((domain, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            return cert
                except Exception as e:
                    logger.debug(f"SSL connection failed for {domain}: {e}")
                    return None
            
            cert = await asyncio.wait_for(loop.run_in_executor(None, get_cert), timeout=15)
            
            if not cert:
                return None
            
            # Extract information
            san = cert.get("subjectAltName", [])
            san_domains = [entry[1] for entry in san if entry[0] == "DNS"]
            
            issuer = cert.get("issuer", [])
            issuers = [entry[0][1] for entry in issuer if entry[0][0] == "organizationName"]
            
            return {
                "san": san_domains,
                "issuers": issuers,
                "not_after": cert.get("notAfter"),
                "subject": cert.get("subject"),
            }
            
        except Exception as e:
            logger.debug(f"Certificate info extraction failed for {domain}: {e}")
            return None
    
    async def _check_takeover_risks(self, domain: str, subdomains: Set[str]) -> List[dict]:
        """Check for subdomain takeover vulnerabilities."""
        risks = []
        
        all_domains = {domain} | subdomains
        
        for check_domain in all_domains:
            for suffix, info in self.TAKEOVER_TARGETS.items():
                if check_domain.endswith(suffix):
                    # Check if DNS resolves
                    try:
                        loop = asyncio.get_event_loop()
                        await asyncio.wait_for(
                            loop.run_in_executor(None, socket.gethostbyname, check_domain),
                            timeout=5
                        )
                        # If it resolves, still worth noting as potential risk
                        risks.append({
                            "subdomain": check_domain,
                            "service": info["service"],
                            "vulnerability": info["vulnerability"],
                            "risk_level": "medium",
                            "check": "Verify if the cloud resource still exists",
                        })
                    except asyncio.TimeoutError:
                        # DNS timeout - might indicate dangling CNAME
                        risks.append({
                            "subdomain": check_domain,
                            "service": info["service"],
                            "vulnerability": info["vulnerability"],
                            "risk_level": "high",
                            "check": "Dangling CNAME detected - immediate takeover possible",
                        })
                    except socket.gaierror:
                        # DNS resolution failed - dangling CNAME
                        risks.append({
                            "subdomain": check_domain,
                            "service": info["service"],
                            "vulnerability": info["vulnerability"],
                            "risk_level": "high",
                            "check": "Dangling CNAME detected - immediate takeover possible",
                        })
        
        return risks
    
    async def analyze_domains(self, domains: Set[str]) -> Dict[str, DomainInfo]:
        """Analyze multiple domains concurrently."""
        tasks = [self.analyze_domain(domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            domain: result if not isinstance(result, Exception) else DomainInfo(domain=domain)
            for domain, result in zip(domains, results)
        }
    
    def get_subdomain_enum_targets(self) -> List[str]:
        """Get list of domains suitable for subdomain enumeration."""
        targets = []
        for domain, info in self._cache.items():
            if info.has_ct_logs and len(info.subdomains) > 0:
                targets.append(domain)
        return targets
    
    def get_takeover_targets(self) -> List[dict]:
        """Get all potential subdomain takeover targets."""
        targets = []
        for domain, info in self._cache.items():
            for risk in info.subdomain_takeover_risks:
                if risk["risk_level"] == "high":
                    targets.append({
                        "domain": domain,
                        **risk,
                    })
        return targets


# Global monitor instance
ct_monitor = CertificateTransparencyMonitor()
