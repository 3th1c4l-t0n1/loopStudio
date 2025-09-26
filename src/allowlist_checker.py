#!/usr/bin/env python3
"""
Allowlist Checker Module
Checks indicators against allowlists to filter out false positives
"""

import json
import logging
import yaml
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class AllowlistResult:
    """Represents the result of an allowlist check"""
    indicator: str
    indicator_type: str
    is_allowlisted: bool
    allowlist_source: Optional[str] = None
    reason: Optional[str] = None

@dataclass
class AllowlistCheck:
    """Represents a comprehensive allowlist check result"""
    total_indicators: int
    allowlisted_indicators: int
    suspicious_indicators: int
    results: List[AllowlistResult]

class AllowlistChecker:
    """Checks indicators against allowlists"""
    
    def __init__(self, allowlist_file: str = "SOAR_Samples/configs/allowlists.yml"):
        self.allowlist_data = self._load_allowlist(allowlist_file)
        self.check_results = []
        
    def _load_allowlist(self, allowlist_file: str) -> Dict[str, Any]:
        """Load allowlist configuration"""
        try:
            with open(allowlist_file, 'r') as f:
                allowlist = yaml.safe_load(f)
            logger.info(f"Loaded allowlist from {allowlist_file}")
            return allowlist
        except Exception as e:
            logger.error(f"Error loading allowlist: {e}")
            return {}
    
    def _check_ipv4_allowlist(self, ip: str) -> AllowlistResult:
        """Check IPv4 address against allowlist"""
        allowlisted_ips = self.allowlist_data.get('indicators', {}).get('ipv4', [])
        
        is_allowlisted = ip in allowlisted_ips
        reason = f"IP {ip} is {'allowlisted' if is_allowlisted else 'not allowlisted'}"
        
        return AllowlistResult(
            indicator=ip,
            indicator_type="ipv4",
            is_allowlisted=is_allowlisted,
            allowlist_source="allowlist_config",
            reason=reason
        )
    
    def _check_domain_allowlist(self, domain: str) -> AllowlistResult:
        """Check domain against allowlist"""
        allowlisted_domains = self.allowlist_data.get('indicators', {}).get('domains', [])
        
        is_allowlisted = domain in allowlisted_domains
        reason = f"Domain {domain} is {'allowlisted' if is_allowlisted else 'not allowlisted'}"
        
        return AllowlistResult(
            indicator=domain,
            indicator_type="domains",
            is_allowlisted=is_allowlisted,
            allowlist_source="allowlist_config",
            reason=reason
        )
    
    def _check_asset_allowlist(self, device_id: str) -> bool:
        """Check if asset is in allowlist"""
        allowlisted_assets = self.allowlist_data.get('assets', {}).get('device_ids', [])
        return device_id in allowlisted_assets
    
    def check_indicators(self, indicators: Dict[str, List[str]], 
                        asset_info: Optional[Dict[str, Any]] = None) -> AllowlistCheck:
        """Check all indicators against allowlists"""
        results = []
        
        # Check if asset is allowlisted
        asset_allowlisted = False
        if asset_info and 'device_id' in asset_info:
            asset_allowlisted = self._check_asset_allowlist(asset_info['device_id'])
            if asset_allowlisted:
                logger.info(f"Asset {asset_info['device_id']} is allowlisted - all indicators may be false positives")
        
        # Check IPv4 addresses
        for ip in indicators.get('ipv4', []):
            result = self._check_ipv4_allowlist(ip)
            results.append(result)
        
        # Check domains
        for domain in indicators.get('domains', []):
            result = self._check_domain_allowlist(domain)
            results.append(result)
        
        # URLs are not directly allowlisted but may contain allowlisted domains
        for url in indicators.get('urls', []):
            # Extract domain from URL
            try:
                from urllib.parse import urlparse
                parsed_url = urlparse(url)
                if parsed_url.netloc:
                    result = self._check_domain_allowlist(parsed_url.netloc)
                    result.indicator = url  # Keep original URL as indicator
                    result.indicator_type = "urls"
                    results.append(result)
            except Exception as e:
                logger.warning(f"Could not parse URL {url}: {e}")
                # If URL can't be parsed, assume not allowlisted
                results.append(AllowlistResult(
                    indicator=url,
                    indicator_type="urls",
                    is_allowlisted=False,
                    reason="URL could not be parsed for allowlist check"
                ))
        
        # SHA256 hashes are typically not allowlisted
        for sha256 in indicators.get('sha256', []):
            results.append(AllowlistResult(
                indicator=sha256,
                indicator_type="sha256",
                is_allowlisted=False,
                reason="SHA256 hashes are not typically allowlisted"
            ))
        
        # Calculate summary
        total_indicators = len(results)
        allowlisted_indicators = sum(1 for r in results if r.is_allowlisted)
        suspicious_indicators = total_indicators - allowlisted_indicators
        
        # If asset is allowlisted, mark all indicators as potentially false positives
        if asset_allowlisted:
            for result in results:
                if not result.is_allowlisted:
                    result.reason = f"{result.reason} - Asset is allowlisted"
        
        check_result = AllowlistCheck(
            total_indicators=total_indicators,
            allowlisted_indicators=allowlisted_indicators,
            suspicious_indicators=suspicious_indicators,
            results=results
        )
        
        self.check_results.append(check_result)
        logger.info(f"Allowlist check completed: {allowlisted_indicators}/{total_indicators} allowlisted")
        return check_result
    

