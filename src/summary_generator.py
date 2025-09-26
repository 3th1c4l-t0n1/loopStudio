#!/usr/bin/env python3
"""
Summary Generator Module
Generates analyst summaries using Jinja2 templates and exports to Markdown
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from jinja2 import Environment, FileSystemLoader, Template
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global summary counter
_summary_counter = 0
_summary_lock = threading.Lock()

def get_next_summary_number() -> int:
    """Get the next sequential summary number"""
    global _summary_counter
    with _summary_lock:
        if _summary_counter == 0:
            # Initialize counter from existing files
            _summary_counter = _get_max_summary_number()
        _summary_counter += 1
        return _summary_counter

def _get_max_summary_number() -> int:
    """Get the highest summary number from existing files"""
    summaries_dir = "out/summaries"
    if not os.path.exists(summaries_dir):
        return 0
    
    max_num = 0
    for filename in os.listdir(summaries_dir):
        if filename.startswith("sum-inc-") and filename.endswith(".md"):
            try:
                # Extract number from filename like "sum-inc-001.md"
                num_str = filename[8:-3]  # Remove "sum-inc-" and ".md"
                num = int(num_str)
                max_num = max(max_num, num)
            except ValueError:
                continue
    return max_num

@dataclass
class IncidentSummary:
    """Represents a complete incident summary"""
    incident_id: str
    alert_type: str
    source: str
    created_at: str
    severity: str
    status: str
    asset: Dict[str, Any]
    indicators: Dict[str, List[str]]
    enriched_indicators: Dict[str, List[Dict[str, Any]]]
    mitre_techniques: List[str]
    mitre_confidence: int
    risk_score: int
    investigation_required: bool
    recommendations: List[str]
    actions_taken: List[str]
    tags: List[str]
    processing_time: float
    analyst_notes: Optional[str] = None

class SummaryGenerator:
    """Generates analyst summaries using Jinja2 templates"""
    
    def __init__(self, templates_dir: str = "templates", output_dir: str = "out/summaries"):
        self.templates_dir = templates_dir
        self.output_dir = output_dir
        self.jinja_env = None
        self._setup_directories()
        self._setup_jinja()
        
    def _setup_directories(self):
        """Create necessary directories if they don't exist"""
        os.makedirs(self.templates_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(f"Created directories: {self.templates_dir}, {self.output_dir}")
    
    def _setup_jinja(self):
        """Setup Jinja2 environment"""
        try:
            self.jinja_env = Environment(
                loader=FileSystemLoader(self.templates_dir),
                autoescape=True,
                trim_blocks=True,
                lstrip_blocks=True
            )
            logger.info("Jinja2 environment initialized")
        except Exception as e:
            logger.error(f"Error setting up Jinja2: {e}")
            # Fallback to basic template
            self.jinja_env = None
    
    def _determine_severity(self, risk_score: int, investigation_required: bool) -> str:
        """Determine incident severity based on risk score according to requirements"""
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
    
    def _generate_tags(self, alert_type: str, mitre_techniques: List[str], 
                      enriched_indicators: Dict[str, List[Dict[str, Any]]]) -> List[str]:
        """Generate relevant tags for the incident"""
        tags = [alert_type.lower()]
        
        # Add MITRE technique tags
        for technique in mitre_techniques:
            tags.append(f"mitre-{technique}")
        
        # Add indicator type tags
        for indicator_type, ti_results in enriched_indicators.items():
            if ti_results:
                tags.append(f"has-{indicator_type}")
        
        # Add threat level tags
        has_malicious = False
        for ti_results in enriched_indicators.values():
            for ti_result in ti_results:
                if (ti_result.get('reputation') == 'malicious' or 
                    ti_result.get('classification') == 'malicious'):
                    has_malicious = True
                    break
        
        if has_malicious:
            tags.append("malicious-indicators")
        
        return list(set(tags))  # Remove duplicates
    
    def _generate_actions_taken(self, investigation_required: bool, recommendations: List[str]) -> List[str]:
        """Generate list of actions taken based on analysis"""
        actions = []
        
        if investigation_required:
            actions.append("Alert escalated for investigation")
            actions.append("Threat intelligence enrichment completed")
            actions.append("MITRE ATT&CK mapping performed")
            actions.append("Allowlist verification completed")
        
        # Add specific actions based on recommendations
        for rec in recommendations:
            if "Block" in rec:
                actions.append("Indicators blocked")
            elif "Quarantine" in rec:
                actions.append("Files quarantined")
            elif "Monitor" in rec:
                actions.append("Network monitoring enhanced")
            elif "Review" in rec:
                actions.append("Security controls reviewed")
        
        return actions
    
    def create_incident_summary(self, soar_result: Dict[str, Any], 
                               analyst_notes: Optional[str] = None) -> IncidentSummary:
        """Create a comprehensive incident summary from SOAR result"""
        
        # Determine severity
        severity = self._determine_severity(
            soar_result.get('risk_score', 0),
            soar_result.get('investigation_required', False)
        )
        
        # Generate tags
        tags = self._generate_tags(
            soar_result.get('alert_type', ''),
            soar_result.get('mitre_mapping', {}).get('techniques', []),
            soar_result.get('enriched_indicators', {})
        )
        
        # Generate actions taken
        actions_taken = self._generate_actions_taken(
            soar_result.get('investigation_required', False),
            soar_result.get('recommendations', [])
        )
        
        # Use incident ID from SOAR result
        incident_id = soar_result.get('incident_id', 'inc-unknown')
        
        # Create incident summary
        summary = IncidentSummary(
            incident_id=incident_id,
            alert_type=soar_result.get('alert_type', 'Unknown'),
            source=soar_result.get('source', 'Unknown'),
            created_at=soar_result.get('created_at', datetime.now().isoformat()),
            severity=severity,
            status="Open" if soar_result.get('investigation_required', False) else "Closed",
            asset=soar_result.get('asset', {}),
            indicators=soar_result.get('indicators', {}),
            enriched_indicators=soar_result.get('enriched_indicators', {}),
            mitre_techniques=soar_result.get('mitre_mapping', {}).get('techniques', []),
            mitre_confidence=soar_result.get('mitre_mapping', {}).get('confidence', 0),
            risk_score=soar_result.get('risk_score', 0),
            investigation_required=soar_result.get('investigation_required', False),
            recommendations=soar_result.get('recommendations', []),
            actions_taken=actions_taken,
            tags=tags,
            processing_time=soar_result.get('processing_time', 0),
            analyst_notes=analyst_notes
        )
        
        logger.info(f"Created incident summary for {summary.incident_id}")
        return summary
    
    def generate_markdown_summary(self, incident_summary: IncidentSummary) -> str:
        """Generate Markdown summary using Jinja2 template"""
        
        if self.jinja_env:
            try:
                template = self.jinja_env.get_template('incident_summary.md')
                return template.render(incident=incident_summary)
            except Exception as e:
                logger.warning(f"Error using Jinja2 template: {e}, falling back to basic template")
        
        # Fallback to basic template
        return self._generate_basic_markdown(incident_summary)
    
    def _generate_basic_markdown(self, incident_summary: IncidentSummary) -> str:
        """Generate basic Markdown summary without Jinja2"""
        
        markdown = f"""# Incident Summary: {incident_summary.incident_id}

## Basic Information
- **Alert Type**: {incident_summary.alert_type}
- **Source**: {incident_summary.source}
- **Severity**: {incident_summary.severity}
- **Status**: {incident_summary.status}
- **Created**: {incident_summary.created_at}
- **Risk Score**: {incident_summary.risk_score}/100

## Asset Information
- **Device ID**: {incident_summary.asset.get('device_id', 'N/A')}
- **Hostname**: {incident_summary.asset.get('hostname', 'N/A')}
- **IP Address**: {incident_summary.asset.get('ip', 'N/A')}

## Indicators

### IPv4 Addresses
"""
        
        for ip in incident_summary.indicators.get('ipv4', []):
            markdown += f"- {ip}\n"
        
        markdown += "\n### Domains\n"
        for domain in incident_summary.indicators.get('domains', []):
            markdown += f"- {domain}\n"
        
        markdown += "\n### URLs\n"
        for url in incident_summary.indicators.get('urls', []):
            markdown += f"- {url}\n"
        
        markdown += "\n### SHA256 Hashes\n"
        for sha256 in incident_summary.indicators.get('sha256', []):
            markdown += f"- {sha256}\n"
        
        markdown += f"""
## Threat Intelligence Enrichment

"""
        
        for indicator_type, ti_results in incident_summary.enriched_indicators.items():
            if ti_results:
                markdown += f"### {indicator_type.title()}\n"
                for ti_result in ti_results:
                    markdown += f"- **{ti_result.get('indicator', 'N/A')}**: "
                    if ti_result.get('reputation'):
                        markdown += f"Reputation: {ti_result['reputation']}"
                    if ti_result.get('classification'):
                        markdown += f", Classification: {ti_result['classification']}"
                    if ti_result.get('risk_score'):
                        markdown += f", Risk Score: {ti_result['risk_score']}"
                    markdown += "\n"
        
        markdown += f"""
## MITRE ATT&CK Techniques
- **Techniques**: {', '.join(incident_summary.mitre_techniques)}
- **Confidence**: {incident_summary.mitre_confidence}%

## Security Recommendations
"""
        
        for rec in incident_summary.recommendations:
            markdown += f"- {rec}\n"
        
        markdown += f"""
## Actions Taken
"""
        
        for action in incident_summary.actions_taken:
            markdown += f"- {action}\n"
        
        markdown += f"""
## Tags
{', '.join(incident_summary.tags)}

## Processing Information
- **Processing Time**: {incident_summary.processing_time:.3f} seconds
- **Investigation Required**: {'Yes' if incident_summary.investigation_required else 'No'}
"""
        
        if incident_summary.analyst_notes:
            markdown += f"""
## Analyst Notes
{incident_summary.analyst_notes}
"""
        
        return markdown
    
    def save_summary(self, incident_summary: IncidentSummary, 
                    markdown_content: str) -> str:
        """Save incident summary to file"""
        
        # Use incident ID for summary filename
        filename = f"sum-{incident_summary.incident_id}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            logger.info(f"Saved incident summary to {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error saving summary to {filepath}: {e}")
            raise
    
    def generate_and_save_summary(self, soar_result: Dict[str, Any], 
                                 analyst_notes: Optional[str] = None) -> str:
        """Generate and save incident summary in one operation"""
        
        # Create incident summary
        incident_summary = self.create_incident_summary(soar_result, analyst_notes)
        
        # Generate Markdown content
        markdown_content = self.generate_markdown_summary(incident_summary)
        
        # Save to file
        filepath = self.save_summary(incident_summary, markdown_content)
        
        return filepath
    
    def generate_batch_summaries(self, soar_results: List[Dict[str, Any]], 
                                analyst_notes: Optional[Dict[str, str]] = None) -> List[str]:
        """Generate summaries for multiple incidents"""
        
        generated_files = []
        
        for soar_result in soar_results:
            # Use incident ID from SOAR result
            incident_id = soar_result.get('incident_id', 'inc-unknown')
            notes = analyst_notes.get(incident_id) if analyst_notes else None
            
            try:
                filepath = self.generate_and_save_summary(soar_result, notes)
                generated_files.append(filepath)
            except Exception as e:
                logger.error(f"Error generating summary for {incident_id}: {e}")
        
        logger.info(f"Generated {len(generated_files)} incident summaries")
        return generated_files

