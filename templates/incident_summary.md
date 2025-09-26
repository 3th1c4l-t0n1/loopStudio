# 🚨 **ALERT SUMMARY**

---

## 📋 **INCIDENT**

| **Field** | **Value** |
|-----------|-----------|
| **Incident ID** | **{{ incident.incident_id }}** |
| **Alert Type** | {{ incident.alert_type }} |
| **Source** | {{ incident.source }} |
| **Severity** | {% if incident.severity == "Critical" %}🔴 **CRITICAL**{% elif incident.severity == "High" %}🟠 **HIGH**{% elif incident.severity == "Medium" %}🟡 **MEDIUM**{% else %}🟢 **LOW**{% endif %} |
| **Risk Score** | **{{ incident.risk_score }}/100** |
| **Created** | {{ incident.created_at }} |
| **Investigation Required** | {% if incident.investigation_required %}✅ **YES**{% else %}❌ **NO**{% endif %} |
| **Status** | {% if incident.status == "Open" %}🔴 **OPEN**{% else %}✅ **CLOSED**{% endif %} |

---

## 🖥️ **AFFECTED ASSET**

| **🆔 DEVICE ID** | **💻 HOSTNAME** | **🌐 IP ADDRESS** |
|:---:|:---:|:---:|
| **{{ incident.asset.device_id or 'N/A' }}** | **{{ incident.asset.hostname or 'N/A' }}** | **{{ incident.asset.ip or 'N/A' }}** |

---

## 📊 **IoC**

| **Type** | **Value** | **Reputation** | **Score** | **Details** |
|:---:|:---:|:---:|:---:|:---:|
{% if incident.indicators.ipv4 %}
{% for ip in incident.indicators.ipv4 %}
| **IPv4** | `{{ ip }}` | {% for ti_result in incident.enriched_indicators.ipv4 %}{% if ti_result.indicator == ip %}{% if ti_result.reputation == 'malicious' %}🔴 **MALICIOUS**{% elif ti_result.reputation == 'suspicious' %}🟡 **SUSPICIOUS**{% else %}🟢 **CLEAN**{% endif %}{% endif %}{% endfor %} | {% for ti_result in incident.enriched_indicators.ipv4 %}{% if ti_result.indicator == ip %}{% if ti_result.risk_score and ti_result.risk_score != 'suspicious' %}{{ ti_result.risk_score }}{% else %}-{% endif %}{% endif %}{% endfor %} | {% for ti_result in incident.enriched_indicators.ipv4 %}{% if ti_result.indicator == ip %}{{ ti_result.confidence or 'N/A' }}% confidence{% endif %}{% endfor %} |
{% endfor %}
{% endif %}
{% if incident.indicators.domains %}
{% for domain in incident.indicators.domains %}
| **Domain** | `{{ domain }}` | {% for ti_result in incident.enriched_indicators.domains %}{% if ti_result.indicator == domain and loop.first %}{% if ti_result.reputation == 'malicious' %}🔴 **MALICIOUS**{% elif ti_result.reputation == 'suspicious' %}🟡 **SUSPICIOUS**{% else %}🟢 **CLEAN**{% endif %}{% endif %}{% endfor %} | {% for ti_result in incident.enriched_indicators.domains %}{% if ti_result.indicator == domain and loop.first %}{{ ti_result.risk_score or 'N/A' }}{% endif %}{% endfor %} | {% for ti_result in incident.enriched_indicators.domains %}{% if ti_result.indicator == domain and loop.first %}{{ ti_result.categories|join(', ') if ti_result.categories else 'N/A' }}{% endif %}{% endfor %} |
{% endfor %}
{% endif %}
{% if incident.indicators.urls %}
{% for url in incident.indicators.urls %}
| **URL** | `{{ url }}` | - | - | - |
{% endfor %}
{% endif %}
{% if incident.indicators.sha256 %}
{% for sha256 in incident.indicators.sha256 %}
| **SHA256** | `{{ sha256 }}` | {% for ti_result in incident.enriched_indicators.sha256 %}{% if ti_result.indicator == sha256 %}{% if ti_result.classification == 'malicious' %}🔴 **MALICIOUS**{% elif ti_result.classification == 'suspicious' %}🟡 **SUSPICIOUS**{% else %}🟢 **CLEAN**{% endif %}{% endif %}{% endfor %} | {% for ti_result in incident.enriched_indicators.sha256 %}{% if ti_result.indicator == sha256 %}{{ ti_result.risk_score or 'N/A' }}{% endif %}{% endfor %} | {% for ti_result in incident.enriched_indicators.sha256 %}{% if ti_result.indicator == sha256 %}{{ ti_result.threat_name or 'Unknown' }}{% endif %}{% endfor %} |
{% endfor %}
{% endif %}

---

## 🏷️ **SEVERITY & TAGS**

| **Field** | **Value** |
|-----------|-----------|
| **Severity** | {% if incident.severity == "Critical" %}🔴 **CRITICAL**{% elif incident.severity == "High" %}🟠 **HIGH**{% elif incident.severity == "Medium" %}🟡 **MEDIUM**{% else %}🟢 **LOW**{% endif %} |
| **Risk Score** | **{{ incident.risk_score }}/100** |
| **Tags** | {{ incident.tags|join(', ') if incident.tags else 'None' }} |

---

## 🎯 **ATT&CK TECHNIQUES**

| **Technique** | **Description** | **Tactic** |
|:---:|:---:|:---:|
{% for technique in incident.mitre_techniques %}
| **{{ technique }}** | {% if technique == "T1056" %}Input Capture{% elif technique == "T1555" %}Credentials from Password Stores{% elif technique == "T1071" %}Application Layer Protocol{% elif technique == "T1071.001" %}Web Protocols{% elif technique == "T1566" %}Phishing{% elif technique == "T1204" %}User Execution{% elif technique == "T1204.002" %}User Execution: Malicious File{% elif technique == "T1105" %}Ingress Tool Transfer{% elif technique == "T1566.001" %}Phishing: Spearphishing Attachment{% elif technique == "T1566.002" %}Phishing: Spearphishing Link{% else %}Unknown Technique{% endif %} | {% if technique.startswith("T1") %}**Initial Access**{% elif technique.startswith("T15") %}**Credential Access**{% elif technique.startswith("T10") %}**Execution**{% elif technique.startswith("T11") %}**Persistence**{% else %}**Unknown**{% endif %} |
{% endfor %}

---

## ✅ **ACTIONS TAKEN**

{% for action in incident.actions_taken %}
- {{ action }}
{% endfor %}

---

<div align="center">

**🔒 SOAR SYSTEM** | **📅 Generated**: {{ incident.created_at }}
**Security Orchestration, Automation and Response** | **🤖 Automated Report**

</div>