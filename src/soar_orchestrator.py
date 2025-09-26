#!/usr/bin/env python3
"""
SOAR Orchestrator - Main System Coordinator

This is the central orchestrator that coordinates all SOAR system components.
It manages the complete workflow from alert ingestion through final output
generation, including TI enrichment, risk assessment, and response actions.
"""

import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from .incident_generator import get_next_incident_number

def get_new_incident_id() -> str:
    """Generate new incident ID in format inc-XXX"""
    incident_number = get_next_incident_number()
    return f"inc-{incident_number:03d}"

from .alert_processor import AlertProcessor, Alert
from .ti_enrichment import TIEnrichment, TIResult
from .mitre_mapping import MITREMapper, MITREMapping
from .allowlist_checker import AllowlistChecker, AllowlistCheck
from .config_loader import ConfigLoader, SOARConfig
from .summary_generator import SummaryGenerator, IncidentSummary
from .device_isolation import DeviceIsolation
from .incident_generator import IncidentGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SOARResult:
    """SOAR processing result"""
    alert_id: str
    incident_id: str
    alert_type: str
    source: str
    created_at: str
    asset: Dict[str, Any]
    indicators: Dict[str, List[str]]
    enriched_indicators: Dict[str, List[TIResult]]
    mitre_mapping: MITREMapping
    allowlist_check: AllowlistCheck
    risk_score: int
    investigation_required: bool
    recommendations: List[str]
    processing_time: float
    tags: List[str] = field(default_factory=list)

class SOAROrchestrator:
    """Main SOAR orchestrator"""
    
    def __init__(self, config_dir: str = "SOAR_Samples/configs"):
        self.config_loader = ConfigLoader(config_dir)
        self.config = self.config_loader.load_config()
        
        # Initialize components
        self.alert_processor = AlertProcessor()
        self.ti_enrichment = TIEnrichment()
        self.mitre_mapper = MITREMapper()
        self.allowlist_checker = AllowlistChecker()
        self.summary_generator = SummaryGenerator()
        self.device_isolation = DeviceIsolation()
        self.incident_generator = IncidentGenerator()
        
        self.processing_results = []
        
        logger.info("SOAR Orchestrator initialized")
    
    def process_alert(self, alert_file: str) -> SOARResult:
        """Process a single alert through the complete SOAR pipeline"""
        start_time = time.time()
        
        try:
            # Load and normalize the alert data
            logger.info(f"Processing alert from {alert_file}")
            alert = self.alert_processor.process_alert(alert_file)
            
            # Enrich indicators with threat intelligence from multiple providers
            logger.info(f"Enriching indicators for alert {alert.alert_id}")
            enriched_indicators = self.ti_enrichment.enrich_indicators(alert.indicators)
            
            # Map alert and indicators to MITRE ATT&CK techniques
            logger.info(f"Mapping MITRE techniques for alert {alert.alert_id}")
            mitre_mapping = self.mitre_mapper.create_mapping(
                alert.alert_type, 
                alert.indicators, 
                enriched_indicators
            )
            
            # Check indicators against allowlists to reduce false positives
            logger.info(f"Checking allowlists for alert {alert.alert_id}")
            allowlist_check = self.allowlist_checker.check_indicators(
                alert.indicators, 
                alert.asset
            )
            
            # Calculate final risk score considering all factors
            final_risk_score, tags = self._calculate_final_risk_score(
                alert, enriched_indicators, allowlist_check, mitre_mapping
            )
            
            # Step 6: Determine if investigation is required
            investigation_required = self._should_investigate(
                alert, enriched_indicators, allowlist_check, final_risk_score
            )
            
            # Step 7: Generate recommendations
            recommendations = self._generate_recommendations(
                alert, enriched_indicators, mitre_mapping, allowlist_check
            )
            
            # Step 8: Check for device isolation
            device_id = alert.asset.get('device_id', '')
            is_allowlisted = any(result.is_allowlisted for result in allowlist_check.results)
            should_isolate = self.device_isolation.should_isolate_device(
                final_risk_score, device_id, is_allowlisted
            )
            
            # Generate incident ID once for consistency
            new_incident_id = get_new_incident_id()
            
            if should_isolate:
                self.device_isolation.isolate_device(device_id, new_incident_id)
                recommendations.append(f"Device {device_id} isolated due to high severity")
            
            # Create result
            processing_time = time.time() - start_time
            result = SOARResult(
                alert_id=alert.alert_id,
                incident_id=new_incident_id,
                alert_type=alert.alert_type,
                source=alert.source,
                created_at=alert.created_at,
                asset=alert.asset,
                indicators=alert.indicators,
                enriched_indicators=enriched_indicators,
                mitre_mapping=mitre_mapping,
                allowlist_check=allowlist_check,
                risk_score=final_risk_score,
                investigation_required=investigation_required,
                recommendations=recommendations,
                processing_time=processing_time,
                tags=tags
            )
            
            self.processing_results.append(result)
            logger.info(f"Alert {alert.alert_id} processed in {processing_time:.2f}s")
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing alert {alert_file}: {e}")
            raise
    
    def _calculate_final_risk_score(self, alert: Alert, enriched_indicators: Dict[str, List[TIResult]], 
                                   allowlist_check: AllowlistCheck, mitre_mapping: MITREMapping) -> int:
        """Calculate final risk score with TI boosts and allowlist suppression"""
        base_score = alert.risk_score or 50
        
        ti_boosts = self.config.ti_boosts or {}
        malicious_boost = ti_boosts.get('malicious_boost', 20)
        suspicious_boost = ti_boosts.get('suspicious_boost', 10)
        extra_flagged_boost = ti_boosts.get('extra_flagged_boost', 5)
        max_extra_boost = ti_boosts.get('max_extra_boost', 20)
        
        malicious_count = 0
        suspicious_count = 0
        ti_boost = 0
        
        for ti_results in enriched_indicators.values():
            for ti_result in ti_results:
                if (hasattr(ti_result, 'reputation') and ti_result.reputation == "malicious") or \
                   (hasattr(ti_result, 'classification') and ti_result.classification == "malicious"):
                    malicious_count += 1
                elif (hasattr(ti_result, 'reputation') and ti_result.reputation == "suspicious") or \
                     (hasattr(ti_result, 'risk_score') and isinstance(ti_result.risk_score, (int, float)) and ti_result.risk_score > 70):
                    suspicious_count += 1
        
        if malicious_count > 0:
            ti_boost += malicious_boost
        
        if suspicious_count > 0:
            ti_boost += suspicious_boost
        
        total_flagged = malicious_count + suspicious_count
        if total_flagged > 1:
            extra_boost = min((total_flagged - 1) * extra_flagged_boost, max_extra_boost)
            ti_boost += extra_boost
        
        allowlist_config = self.config.allowlist_suppression or {}
        indicator_penalty = allowlist_config.get('indicator_penalty', 25)
        all_allowlisted_severity = allowlist_config.get('all_allowlisted_severity', 0)
        
        allowlist_adjustment = 0
        tags = []
        
        if allowlist_check.allowlisted_indicators > 0:
            allowlist_adjustment = -indicator_penalty * allowlist_check.allowlisted_indicators
            tags.append("allowlisted")
        
        if allowlist_check.allowlisted_indicators == allowlist_check.total_indicators and allowlist_check.total_indicators > 0:
            return all_allowlisted_severity, tags + ["suppressed=true"]
        
        final_score = base_score + ti_boost + allowlist_adjustment
        final_score = max(0, min(100, final_score))
        
        return final_score, tags
    
    def _get_severity_bucket(self, risk_score: int) -> str:
        """Get severity bucket according to requirements: 0=Suppressed, 1–39 Low, 40–69 Medium, 70–89 High, 90–100 Critical"""
        if risk_score == 0:
            return "Suppressed"
        elif 1 <= risk_score <= 39:
            return "Low"
        elif 40 <= risk_score <= 69:
            return "Medium"
        elif 70 <= risk_score <= 89:
            return "High"
        elif 90 <= risk_score <= 100:
            return "Critical"
        else:
            return "Unknown"
    
    def _should_investigate(self, alert: Alert, enriched_indicators: Dict[str, List[TIResult]], 
                          allowlist_check: AllowlistCheck, risk_score: int) -> bool:
        """Determine if alert requires investigation"""
        # High risk score
        if risk_score >= self.config.risk_threshold:
            return True
        
        # Malicious indicators
        for ti_results in enriched_indicators.values():
            for ti_result in ti_results:
                if (hasattr(ti_result, 'reputation') and ti_result.reputation == "malicious" or 
                    hasattr(ti_result, 'classification') and ti_result.classification == "malicious" or
                    (hasattr(ti_result, 'risk_score') and ti_result.risk_score and isinstance(ti_result.risk_score, (int, float)) and ti_result.risk_score > 90)):
                    return True
        
        # Multiple suspicious indicators
        if allowlist_check.suspicious_indicators >= 2:
            return True
        
        # Critical alert types
        critical_types = ["Malware", "C2", "CredentialAccess"]
        if alert.alert_type in critical_types:
            return True
        
        return False
    
    def _generate_recommendations(self, alert: Alert, enriched_indicators: Dict[str, List[TIResult]], 
                                mitre_mapping: MITREMapping, allowlist_check: AllowlistCheck) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # MITRE-based recommendations
        if "T1555" in mitre_mapping.techniques:
            recommendations.append("Review credential storage and access controls")
        if "T1566" in mitre_mapping.techniques:
            recommendations.append("Implement email security controls and user training")
        if "T1071" in mitre_mapping.techniques:
            recommendations.append("Monitor network traffic for suspicious communications")
        if "T1204" in mitre_mapping.techniques:
            recommendations.append("Implement application whitelisting and execution controls")
        
        # TI-based recommendations
        for ti_results in enriched_indicators.values():
            for ti_result in ti_results:
                if ti_result.reputation == "malicious":
                    recommendations.append(f"Block malicious indicator: {ti_result.indicator}")
                if ti_result.classification == "malicious":
                    recommendations.append(f"Quarantine and analyze file: {ti_result.indicator}")
        
        # Allowlist-based recommendations
        if allowlist_check.allowlisted_indicators > 0:
            recommendations.append("Review allowlist entries for potential false positives")
        
        # Asset-specific recommendations
        if alert.asset.get('hostname'):
            recommendations.append(f"Investigate asset: {alert.asset['hostname']}")
        
        # Remove duplicates and return
        return list(set(recommendations))
    
    def process_multiple_alerts(self, alert_files: List[str]) -> List[SOARResult]:
        """Process multiple alerts"""
        results = []
        
        for alert_file in alert_files:
            try:
                result = self.process_alert(alert_file)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to process {alert_file}: {e}")
        
        return results
    
    
    
    def generate_incident_summaries(self, analyst_notes: Optional[Dict[str, str]] = None) -> List[str]:
        """Generate incident summaries for all processed alerts"""
        
        if not self.processing_results:
            logger.warning("No processed alerts to generate summaries for")
            return []
        
        try:
            # Convert SOARResult objects to dictionaries
            soar_results = []
            for result in self.processing_results:
                result_dict = asdict(result)
                # Convert TIResult objects to dicts
                for indicator_type, ti_results in result_dict['enriched_indicators'].items():
                    serialized_results = []
                    for ti_result in ti_results:
                        if hasattr(ti_result, '__dataclass_fields__'):
                            serialized_results.append(asdict(ti_result))
                        elif isinstance(ti_result, dict):
                            serialized_results.append(ti_result)
                        else:
                            serialized_results.append(ti_result.__dict__)
                    result_dict['enriched_indicators'][indicator_type] = serialized_results
                soar_results.append(result_dict)
            
            # Generate summaries
            summary_files = self.summary_generator.generate_batch_summaries(soar_results, analyst_notes)
            
            logger.info(f"Generated {len(summary_files)} incident summaries")
            return summary_files
            
        except Exception as e:
            logger.error(f"Error generating incident summaries: {e}")
            raise
    
    def generate_single_summary(self, alert_id: str, analyst_notes: Optional[str] = None) -> str:
        """Generate incident summary for a specific alert"""
        
        # Find the specific result
        target_result = None
        for result in self.processing_results:
            if result.alert_id == alert_id:
                target_result = result
                break
        
        if not target_result:
            raise ValueError(f"No processed alert found with ID: {alert_id}")
        
        try:
            # Convert to dictionary
            result_dict = asdict(target_result)
            # Convert TIResult objects to dicts
            for indicator_type, ti_results in result_dict['enriched_indicators'].items():
                serialized_results = []
                for ti_result in ti_results:
                    if hasattr(ti_result, '__dataclass_fields__'):
                        serialized_results.append(asdict(ti_result))
                    elif isinstance(ti_result, dict):
                        serialized_results.append(ti_result)
                    else:
                        serialized_results.append(ti_result.__dict__)
                result_dict['enriched_indicators'][indicator_type] = serialized_results
            
            # Generate summary
            summary_file = self.summary_generator.generate_and_save_summary(result_dict, analyst_notes)
            
            logger.info(f"Generated incident summary for {alert_id}: {summary_file}")
            return summary_file
            
        except Exception as e:
            logger.error(f"Error generating summary for {alert_id}: {e}")
            raise
    
    def generate_incident_jsons(self) -> List[str]:
        """Generate incident JSON files for all processed alerts"""
        
        if not self.processing_results:
            logger.warning("No processed alerts to generate incident JSONs for")
            return []
        
        try:
            # Convert SOARResult objects to dictionaries
            soar_results = []
            for result in self.processing_results:
                result_dict = asdict(result)
                # Convert TIResult objects to dicts
                for indicator_type, ti_results in result_dict['enriched_indicators'].items():
                    serialized_results = []
                    for ti_result in ti_results:
                        if hasattr(ti_result, '__dataclass_fields__'):
                            serialized_results.append(asdict(ti_result))
                        elif isinstance(ti_result, dict):
                            serialized_results.append(ti_result)
                        else:
                            serialized_results.append(ti_result.__dict__)
                    result_dict['enriched_indicators'][indicator_type] = serialized_results
                soar_results.append(result_dict)
            
            # Generate incident JSONs
            incident_files = self.incident_generator.generate_batch_incidents(soar_results)
            
            logger.info(f"Generated {len(incident_files)} incident JSON files")
            return incident_files
            
        except Exception as e:
            logger.error(f"Error generating incident JSONs: {e}")
            raise
    

