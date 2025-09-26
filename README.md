# SOAR Developer Async Test

A comprehensive SOAR (Security Orchestration, Automation and Response) system that processes security alerts and generates incident reports with automated threat intelligence enrichment and response actions.

## Features

- **Multi-Platform Alert Processing**: Supports Sentinel, SumoLogic and other alert formats
- **Threat Intelligence Enrichment**: Integrates with Defender TI, ReversingLabs, and Anomali
- **Automated Risk Scoring**: Base scores + TI boosts + allowlist suppression
- **MITRE ATT&CK Mapping**: Automatic technique mapping based on alert types
- **Device Isolation**: Automated isolation for high-risk incidents
- **Professional Reporting**: Jinja2-generated analyst summaries and incident JSONs

## Installation

```bash
# Clone the repository
git clone https://github.com/3th1c4l-t0n1/loopStudio
cd loopStudio

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Process a single alert
python main.py SOAR_Samples/alerts/sentinel.json

# Process multiple alerts
python main.py SOAR_Samples/alerts/sentinel.json SOAR_Samples/alerts/sumologic.json
```

## System Architecture

The system follows a modular pipeline architecture:

### High-Level Workflow
```
Alert Input → Normalization → TI Enrichment → Risk Assessment → MITRE Mapping → Response → Output Generation
```

### Component Interaction Design
The system follows a pipeline architecture where each component processes data and passes it to the next stage:

```
┌─────────────────┐    ┌────────────-──────┐    ┌─────────--────────┐
│   Alert Input   │───▶│  SOAR Orchestrator│───▶│  Output Generation│
└─────────────────┘    └─────────────-─────┘    └───────--──────────┘
                              │
                              ▼
                    ┌─────────────────--─┐
                    │  Core Components   │
                    │  - Alert Processor │
                    │  - TI Enrichment   │
                    │  - MITRE Mapping   │
                    │  - Allowlist Check │
                    │  - Device Isolation│
                    └──────────────────--┘
```

### Core Components

- **Alert Processor**: Normalizes different alert formats into standard structure
- **TI Enrichment**: Enriches IOCs with threat intelligence data
- **Risk Assessment**: Calculates scores with base + TI boosts + allowlist suppression
- **MITRE Mapping**: Maps alert types to ATT&CK techniques
- **Device Isolation**: Automatically isolates high-risk devices
- **Report Generation**: Creates incident JSONs and analyst summaries

## Project Structure

```
loopStudio/
├── src/                           # Source code modules
│   ├── alert_processor.py        # Alert processing and normalization
│   ├── ti_enrichment.py          # Threat intelligence enrichment
│   ├── mitre_mapping.py          # MITRE ATT&CK technique mapping
│   ├── allowlist_checker.py      # Allowlist checking and suppression
│   ├── soar_orchestrator.py      # Main system orchestrator
│   ├── device_isolation.py       # Device isolation logic
│   ├── incident_generator.py     # Incident JSON generation
│   ├── summary_generator.py      # Analyst summary generation
│   └── config_loader.py          # Configuration management
├── SOAR_Samples/                 # Sample data and configurations
│   ├── alerts/                   # Sample alert files
│   ├── configs/                  # YAML configuration files
│   └── mocks/                    # Mock threat intelligence data
├── out/                          # Generated outputs
│   ├── incidents/                # Incident JSON files (inc-XXX.json)
│   ├── summaries/                # Analyst summaries (sum-inc-XXX.md)
│   └── isolation.log             # Device isolation log
├── templates/                    # Jinja2 templates
│   └── incident_summary.md       # Markdown template
└── main.py                       # Entry point
```

## Risk Scoring Logic

The system implements sophisticated risk scoring according to requirements:

### Base Severity Scores
- **Malware**: 70
- **Phishing**: 60  
- **Beaconing**: 65
- **CredentialAccess**: 75
- **C2**: 80
- **Unknown**: 40

### TI Boosts
- **+20**: Any IOC verdict == malicious
- **+10**: Any IOC verdict == suspicious
- **+5**: Per extra flagged IOC beyond the first (cap +20)

### Allowlist Suppression
- **-25**: Per allowlisted IOC
- **Severity = 0**: If all IOCs are allowlisted

### Severity Buckets
- **0**: Suppressed
- **1-39**: Low
- **40-69**: Medium
- **70-89**: High
- **90-100**: Critical

## Outputs

### Incident JSON (`out/incidents/inc-XXX.json`)
Complete incident structure with:
- Incident metadata and source alert
- Asset information and indicators
- Risk assessment and triage data
- MITRE ATT&CK techniques
- Response actions and timeline

### Analyst Summary (`out/summaries/sum-inc-XXX.md`)
Professional Markdown report with:
- Incident overview and severity
- Affected asset information
- IoC analysis with reputation scores
- MITRE ATT&CK techniques
- Actions taken and recommendations

### Isolation Log (`out/isolation.log`)
Device isolation actions:
```
<timestamp> isolate device_id=<ID> incident=<INCIDENT_ID> result=isolated
```

## Configuration

All system parameters are configurable via YAML files in `SOAR_Samples/configs/`:

- **`connectors.yml`**: TI provider configurations and risk scoring parameters
- **`allowlists.yml`**: Allowlist definitions for false positive reduction
- **`mitre_map.yml`**: MITRE ATT&CK technique mappings by alert type

## Usage Examples

```bash
# Process Sentinel alert
python main.py SOAR_Samples/alerts/sentinel.json

# Process SumoLogic alert  
python main.py SOAR_Samples/alerts/sumologic.json

# Process multiple alerts
python main.py SOAR_Samples/alerts/sentinel.json SOAR_Samples/alerts/sumologic.json
```

## Technical Implementation

### Sequential Incident Numbering
- **Incidents**: `inc-001.json`, `inc-002.json`, etc.
- **Summaries**: `sum-inc-001.md`, `sum-inc-002.md`, etc.
- **Independent of alert source**: Works with any platform

### Thread-Safe Counters
- Global counters with thread locks
- Persistent numbering across executions
- Automatic initialization from existing files

### Error Handling
- Comprehensive logging at all levels
- Graceful degradation for missing data
- Validation of all inputs and outputs

## Requirements

- **Python 3.7+**
- **PyYAML**: Configuration management
- **Jinja2**: Template engine for reports
- **requests**: HTTP client for TI providers

## Testing

The system has been thoroughly tested with:
- Multiple alert types and sources
- Various IOC combinations
- Risk scoring edge cases
- Output format validation
- Error handling scenarios
