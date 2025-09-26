#!/usr/bin/env python3
"""
Configuration Loader Module
Loads and manages SOAR system configuration
"""

import json
import logging
import yaml
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TIProvider:
    """Represents a threat intelligence provider configuration"""
    name: str
    base_url: str
    api_key: Optional[str] = None
    timeout: int = 30
    retry_count: int = 3

@dataclass
class EDRConfig:
    """Represents EDR system configuration"""
    name: str
    base_url: str
    api_key: Optional[str] = None
    timeout: int = 30

@dataclass
class SOARConfig:
    """Main SOAR system configuration"""
    ti_providers: Dict[str, TIProvider]
    edr_config: EDRConfig
    allowlist_file: str
    mitre_map_file: str
    log_level: str = "INFO"
    max_concurrent_alerts: int = 10
    risk_threshold: int = 70
    base_risk_scores: Optional[Dict[str, int]] = None
    ti_boosts: Optional[Dict[str, int]] = None
    allowlist_suppression: Optional[Dict[str, int]] = None

class ConfigLoader:
    """Loads and manages SOAR configuration"""
    
    def __init__(self, config_dir: str = "SOAR_Samples/configs"):
        self.config_dir = config_dir
        self.config = None
        
    def load_config(self) -> SOARConfig:
        """Load complete SOAR configuration"""
        try:
            # Load connectors configuration
            connectors_file = os.path.join(self.config_dir, "connectors.yml")
            connectors_config = self._load_yaml_config(connectors_file)
            
            # Load allowlist configuration
            allowlist_file = os.path.join(self.config_dir, "allowlists.yml")
            
            # Load MITRE mapping configuration
            mitre_map_file = os.path.join(self.config_dir, "mitre_map.yml")
            
            # Parse TI providers
            ti_providers = self._parse_ti_providers(connectors_config)
            
            # Parse EDR configuration
            edr_config = self._parse_edr_config(connectors_config)
            
            # Create main configuration
            self.config = SOARConfig(
                ti_providers=ti_providers,
                edr_config=edr_config,
                allowlist_file=allowlist_file,
                mitre_map_file=mitre_map_file,
                base_risk_scores=connectors_config.get('base_risk_scores'),
                ti_boosts=connectors_config.get('ti_boosts'),
                allowlist_suppression=connectors_config.get('allowlist_suppression')
            )
            
            logger.info("SOAR configuration loaded successfully")
            return self.config
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            raise
    
    def _load_yaml_config(self, config_file: str) -> Dict[str, Any]:
        """Load YAML configuration file"""
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_file}")
            return config
        except Exception as e:
            logger.error(f"Error loading YAML config from {config_file}: {e}")
            raise
    
    def _parse_ti_providers(self, connectors_config: Dict[str, Any]) -> Dict[str, TIProvider]:
        """Parse threat intelligence provider configurations"""
        ti_providers = {}
        
        providers_config = connectors_config.get('providers', {})
        
        for provider_name, provider_config in providers_config.items():
            ti_provider = TIProvider(
                name=provider_name,
                base_url=provider_config.get('base_url', ''),
                api_key=provider_config.get('api_key'),
                timeout=provider_config.get('timeout', 30),
                retry_count=provider_config.get('retry_count', 3)
            )
            ti_providers[provider_name] = ti_provider
            logger.info(f"Loaded TI provider: {provider_name}")
        
        return ti_providers
    
    def _parse_edr_config(self, connectors_config: Dict[str, Any]) -> EDRConfig:
        """Parse EDR system configuration"""
        edr_config = connectors_config.get('edr', {})
        
        edr = EDRConfig(
            name="EDR System",
            base_url=edr_config.get('base_url', ''),
            api_key=edr_config.get('api_key'),
            timeout=edr_config.get('timeout', 30)
        )
        
        logger.info(f"Loaded EDR configuration: {edr.base_url}")
        return edr
    
    def get_ti_provider(self, provider_name: str) -> Optional[TIProvider]:
        """Get specific TI provider configuration"""
        if not self.config:
            self.load_config()
        
        return self.config.ti_providers.get(provider_name)
    
    def get_all_ti_providers(self) -> Dict[str, TIProvider]:
        """Get all TI provider configurations"""
        if not self.config:
            self.load_config()
        
        return self.config.ti_providers
    
    def get_edr_config(self) -> EDRConfig:
        """Get EDR configuration"""
        if not self.config:
            self.load_config()
        
        return self.config.edr_config
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return any issues"""
        issues = []
        
        if not self.config:
            issues.append("Configuration not loaded")
            return issues
        
        # Validate TI providers
        for name, provider in self.config.ti_providers.items():
            if not provider.base_url:
                issues.append(f"TI provider {name} missing base_url")
            if not provider.api_key and not provider.base_url.startswith('file://'):
                issues.append(f"TI provider {name} missing api_key")
        
        # Validate EDR configuration
        if not self.config.edr_config.base_url:
            issues.append("EDR configuration missing base_url")
        
        # Validate file paths
        if not os.path.exists(self.config.allowlist_file):
            issues.append(f"Allowlist file not found: {self.config.allowlist_file}")
        
        if not os.path.exists(self.config.mitre_map_file):
            issues.append(f"MITRE map file not found: {self.config.mitre_map_file}")
        
        return issues
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary"""
        if not self.config:
            return {"error": "Configuration not loaded"}
        
        return {
            'ti_providers': list(self.config.ti_providers.keys()),
            'edr_url': self.config.edr_config.base_url,
            'allowlist_file': self.config.allowlist_file,
            'mitre_map_file': self.config.mitre_map_file,
            'log_level': self.config.log_level,
            'max_concurrent_alerts': self.config.max_concurrent_alerts,
            'risk_threshold': self.config.risk_threshold
        }
    
    def update_config(self, updates: Dict[str, Any]) -> None:
        """Update configuration with new values"""
        if not self.config:
            self.load_config()
        
        for key, value in updates.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.info(f"Updated configuration: {key} = {value}")
            else:
                logger.warning(f"Unknown configuration key: {key}")

