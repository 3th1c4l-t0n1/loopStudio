#!/usr/bin/env python3
"""
Device Isolation Module
Handles device isolation based on severity and allowlist status
"""

import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DeviceIsolation:
    """Handles device isolation logic and logging"""
    
    def __init__(self, output_dir: str = "out"):
        self.output_dir = output_dir
        self.isolation_log_file = os.path.join(output_dir, "isolation.log")
        self._ensure_output_directories()
    
    def _ensure_output_directories(self):
        """Create necessary output directories"""
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(f"Created output directory: {self.output_dir}")
    
    def should_isolate_device(self, severity: int, device_id: str, 
                            allowlisted: bool) -> bool:
        """Determine if device should be isolated based on criteria"""
        return (severity >= 70 and 
                device_id and 
                device_id.strip() != "" and 
                not allowlisted)
    
    def isolate_device(self, device_id: str, incident_id: str, 
                      result: str = "isolated") -> str:
        """Log device isolation action"""
        timestamp = datetime.now().isoformat()
        log_entry = f"<{timestamp}> isolate device_id={device_id} incident={incident_id} result={result}"
        
        try:
            with open(self.isolation_log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
            
            logger.info(f"Device isolation logged: {log_entry}")
            return log_entry
            
        except Exception as e:
            logger.error(f"Error logging device isolation: {e}")
            raise
    
    def get_current_session_entries(self) -> List[str]:
        """Get isolation entries from current session only"""
        try:
            if os.path.exists(self.isolation_log_file):
                with open(self.isolation_log_file, 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f.readlines() if line.strip()]
                    # Return only the last 10 entries to avoid clutter
                    return lines[-10:] if len(lines) > 10 else lines
            return []
        except Exception as e:
            logger.error(f"Error reading isolation log: {e}")
            return []

