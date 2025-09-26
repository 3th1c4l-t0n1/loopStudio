#!/usr/bin/env python3
"""
Threat Intelligence Enrichment Module

This module enriches security indicators with threat intelligence data from
multiple providers (Defender TI, ReversingLabs, Anomali). It uses local mock
data files to simulate real TI lookups without requiring internet connectivity.
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TIResult:
    """Represents threat intelligence enrichment result"""
    indicator: str
    indicator_type: str
    provider: str
    confidence: Optional[int] = None
    risk_score: Optional[int] = None
    reputation: Optional[str] = None
    classification: Optional[str] = None
    threat_name: Optional[str] = None
    categories: Optional[List[str]] = None
    sightings: Optional[int] = None
    raw_data: Optional[Dict[str, Any]] = None

class TIEnrichment:
    """Enriches indicators with threat intelligence data"""
    
    def __init__(self, config_file: str = "SOAR_Samples/configs/connectors.yml"):
        self.config = self._load_config(config_file)
        self.enrichment_results = []
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load TI provider configuration"""
        try:
            import yaml
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded TI configuration from {config_file}")
            return config
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}
    
    def _load_mock_ti_data(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Load mock threat intelligence data"""
        mock_file = None
        
        if indicator_type == "ipv4":
            mock_file = f"SOAR_Samples/mocks/it/anomali_ip_{indicator}.json"
        elif indicator_type == "domains":
            mock_file = f"SOAR_Samples/mocks/it/defender_ti_domain_{indicator}.json"
        elif indicator_type == "sha256":
            mock_file = f"SOAR_Samples/mocks/it/reversinglabs_sha256_{indicator}.json"
        
        if mock_file and os.path.exists(mock_file):
            try:
                with open(mock_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading mock TI data from {mock_file}: {e}")
        
        return None
    
    def enrich_ipv4(self, ip: str) -> TIResult:
        """Enrich IPv4 address with threat intelligence"""
        ti_data = self._load_mock_ti_data(ip, "ipv4")
        
        if ti_data:
            result = TIResult(
                indicator=ip,
                indicator_type="ipv4",
                provider="anomali",
                confidence=ti_data.get('confidence'),
                risk_score=ti_data.get('risk'),
                reputation=ti_data.get('risk'),
                sightings=ti_data.get('sightings'),
                raw_data=ti_data
            )
        else:
            # Default values for unknown IPs
            result = TIResult(
                indicator=ip,
                indicator_type="ipv4",
                provider="anomali",
                confidence=0,
                risk_score=0,
                reputation="unknown",
                sightings=0,
                raw_data={}
            )
        
        self.enrichment_results.append(result)
        logger.info(f"Enriched IPv4 {ip}: {result.reputation} (confidence: {result.confidence})")
        return result
    
    def enrich_domain(self, domain: str) -> TIResult:
        """Enrich domain with threat intelligence"""
        ti_data = self._load_mock_ti_data(domain, "domains")
        
        if ti_data:
            result = TIResult(
                indicator=domain,
                indicator_type="domains",
                provider="defender_ti",
                risk_score=ti_data.get('score'),
                reputation=ti_data.get('reputation'),
                categories=ti_data.get('categories'),
                raw_data=ti_data
            )
        else:
            # Default values for unknown domains
            result = TIResult(
                indicator=domain,
                indicator_type="domains",
                provider="defender_ti",
                risk_score=0,
                reputation="unknown",
                categories=[],
                raw_data={}
            )
        
        self.enrichment_results.append(result)
        logger.info(f"Enriched domain {domain}: {result.reputation} (score: {result.risk_score})")
        return result
    
    def enrich_sha256(self, sha256: str) -> TIResult:
        """Enrich SHA256 hash with threat intelligence"""
        ti_data = self._load_mock_ti_data(sha256, "sha256")
        
        if ti_data:
            result = TIResult(
                indicator=sha256,
                indicator_type="sha256",
                provider="reversinglabs",
                risk_score=ti_data.get('score'),
                classification=ti_data.get('classification'),
                threat_name=ti_data.get('threat_name'),
                raw_data=ti_data
            )
        else:
            # Default values for unknown hashes
            result = TIResult(
                indicator=sha256,
                indicator_type="sha256",
                provider="reversinglabs",
                risk_score=0,
                classification="unknown",
                threat_name="Unknown",
                raw_data={}
            )
        
        self.enrichment_results.append(result)
        logger.info(f"Enriched SHA256 {sha256[:16]}...{sha256[-8:]}: {result.classification}")
        return result
    
    def enrich_indicators(self, indicators: Dict[str, List[str]]) -> Dict[str, List[TIResult]]:
        """Enrich all indicators in an alert"""
        enriched = {
            'ipv4': [],
            'domains': [],
            'urls': [],
            'sha256': []
        }
        
        # Enrich IPv4 addresses
        for ip in indicators.get('ipv4', []):
            enriched['ipv4'].append(self.enrich_ipv4(ip))
        
        # Enrich domains
        for domain in indicators.get('domains', []):
            enriched['domains'].append(self.enrich_domain(domain))
        
        # Enrich SHA256 hashes
        for sha256 in indicators.get('sha256', []):
            enriched['sha256'].append(self.enrich_sha256(sha256))
        
        # URLs are not directly enriched but may contain domains/IPs
        for url in indicators.get('urls', []):
            # Extract domain from URL for enrichment
            try:
                from urllib.parse import urlparse
                parsed_url = urlparse(url)
                if parsed_url.netloc:
                    enriched['domains'].append(self.enrich_domain(parsed_url.netloc))
            except Exception as e:
                logger.warning(f"Could not parse URL {url}: {e}")
        
        logger.info(f"Enriched {sum(len(v) for v in enriched.values())} indicators")
        return enriched
    

