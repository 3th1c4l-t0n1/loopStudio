#!/usr/bin/env python3
"""
MITRE ATT&CK Technique Mapping Module

This module maps security alerts and indicators to MITRE ATT&CK techniques
based on alert types and threat intelligence enrichment results. It uses
configurable YAML mappings to provide flexible technique assignment.
"""

import json
import logging
import yaml
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class MITRETechnique:
    """Represents a MITRE ATT&CK technique"""
    technique_id: str
    name: str
    description: str
    tactics: List[str]
    sub_techniques: Optional[List[str]] = None

@dataclass
class MITREMapping:
    """Represents a mapping between alert type and MITRE techniques"""
    alert_type: str
    techniques: List[str]
    confidence: int
    rationale: str

class MITREMapper:
    """Maps security alerts to MITRE ATT&CK techniques"""
    
    def __init__(self, mitre_config_file: str = "SOAR_Samples/configs/mitre_map.yml"):
        self.mitre_config = self._load_mitre_config(mitre_config_file)
        self.mappings = []
        
    def _load_mitre_config(self, config_file: str) -> Dict[str, Any]:
        """Load MITRE mapping configuration"""
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded MITRE configuration from {config_file}")
            return config
        except Exception as e:
            logger.error(f"Error loading MITRE config: {e}")
            return {}
    
    def map_alert_type(self, alert_type: str) -> List[str]:
        """Map alert type to MITRE ATT&CK techniques"""
        alert_type_mappings = self.mitre_config.get('alert_type_mappings', {})
        default_techniques = self.mitre_config.get('default_techniques', [])
        
        # Get techniques for specific alert type
        techniques = alert_type_mappings.get(alert_type, default_techniques)
        
        logger.info(f"Mapped alert type '{alert_type}' to techniques: {techniques}")
        return techniques
    
    def map_indicators_to_techniques(self, indicators: Dict[str, List[str]], 
                                   ti_results: Dict[str, List[Any]]) -> List[str]:
        """Map indicators to MITRE techniques based on TI enrichment"""
        techniques = set()
        indicator_mappings = self.mitre_config.get('indicator_mappings', {})
        
        # Map based on indicator types and TI results
        for indicator_type, indicator_list in indicators.items():
            if not indicator_list:
                continue
                
            # Get TI results for this indicator type
            ti_results_for_type = ti_results.get(indicator_type, [])
            
            # Get mappings for this indicator type
            type_mappings = indicator_mappings.get(indicator_type, {})
            
            for ti_result in ti_results_for_type:
                # Map based on reputation/classification
                if hasattr(ti_result, 'reputation') and ti_result.reputation == "malicious":
                    malicious_techniques = type_mappings.get('malicious', [])
                    techniques.update(malicious_techniques)
                
                if hasattr(ti_result, 'classification') and ti_result.classification == "malicious":
                    malicious_techniques = type_mappings.get('malicious', [])
                    techniques.update(malicious_techniques)
                
                # Map based on risk score
                if hasattr(ti_result, 'risk_score') and isinstance(ti_result.risk_score, (int, float)) and ti_result.risk_score > 80:
                    high_risk_techniques = type_mappings.get('high_risk', [])
                    techniques.update(high_risk_techniques)
                
                # Map based on categories
                if hasattr(ti_result, 'categories') and ti_result.categories:
                    for category in ti_result.categories:
                        if category in type_mappings:
                            techniques.update(type_mappings[category])
                
                # Map based on threat name
                if hasattr(ti_result, 'threat_name') and ti_result.threat_name:
                    threat_name = ti_result.threat_name.lower()
                    if 'infostealer' in threat_name and 'infostealer' in type_mappings:
                        techniques.update(type_mappings['infostealer'])
        
        return list(techniques)
    
    def create_mapping(self, alert_type: str, indicators: Dict[str, List[str]], 
                      ti_results: Dict[str, List[Any]]) -> MITREMapping:
        """Create comprehensive MITRE mapping for an alert"""
        # Get base techniques from alert type
        base_techniques = self.map_alert_type(alert_type)
        
        # Get additional techniques from indicator analysis
        indicator_techniques = self.map_indicators_to_techniques(indicators, ti_results)
        
        # Combine and deduplicate techniques
        all_techniques = list(set(base_techniques + indicator_techniques))
        
        # Calculate confidence based on TI enrichment
        confidence = self._calculate_confidence(indicators, ti_results)
        
        mapping = MITREMapping(
            alert_type=alert_type,
            techniques=all_techniques,
            confidence=confidence,
            rationale=""
        )
        
        self.mappings.append(mapping)
        logger.info(f"Created MITRE mapping for {alert_type}: {len(all_techniques)} techniques")
        return mapping
    
    def _calculate_confidence(self, indicators: Dict[str, List[str]], 
                           ti_results: Dict[str, List[Any]]) -> int:
        """Calculate confidence score for MITRE mapping"""
        base_confidence = 50
        
        # Increase confidence based on TI enrichment
        high_confidence_indicators = 0
        total_indicators = sum(len(v) for v in indicators.values())
        
        for ti_result_list in ti_results.values():
            for ti_result in ti_result_list:
                if (ti_result.risk_score and isinstance(ti_result.risk_score, (int, float)) and ti_result.risk_score > 80) or \
                   ti_result.reputation == "malicious" or \
                   ti_result.classification == "malicious":
                    high_confidence_indicators += 1
        
        if total_indicators > 0:
            confidence_boost = (high_confidence_indicators / total_indicators) * 40
            base_confidence += int(confidence_boost)
        
        return min(base_confidence, 100)
    
    

