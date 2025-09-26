#!/usr/bin/env python3
"""
SOAR System Main Entry Point
"""

import json
import os
import sys
import argparse
from datetime import datetime

from src.soar_orchestrator import SOAROrchestrator

def main():
    """Main entry point for SOAR system"""
    parser = argparse.ArgumentParser(description='SOAR Security Orchestration System')
    parser.add_argument('alerts', nargs='*', help='Alert files to process')
    
    args = parser.parse_args()
    
    print("🔒 SOAR Security Orchestration System")
    print("=" * 50)
    
    try:
        # Initialize SOAR orchestrator
        print("Initializing SOAR system...")
        orchestrator = SOAROrchestrator()
        
        # Clear isolation log for clean demo
        isolation_log_path = "out/isolation.log"
        if os.path.exists(isolation_log_path):
            os.remove(isolation_log_path)
        
        # Determine alert files to process
        if args.alerts:
            alert_files = args.alerts
        else:
            # Default to sample alerts
            alert_files = [
                "SOAR_Samples/alerts/sentinel.json",
                "SOAR_Samples/alerts/sumologic.json"
            ]
        
        # Filter existing files
        existing_files = [f for f in alert_files if os.path.exists(f)]
        if not existing_files:
            print("❌ No alert files found to process")
            return 1
        
        print(f"📊 Processing {len(existing_files)} alert(s)...")
        
        # Process alerts
        results = orchestrator.process_multiple_alerts(existing_files)
        
        # Display results
        print("\n📋 Processing Results:")
        print("-" * 30)
        
        for i, result in enumerate(results, 1):
            print(f"\n{i}. Alert {result.alert_id}")
            print(f"   Type: {result.alert_type}")
            print(f"   Source: {result.source}")
            print(f"   Risk Score: {result.risk_score}/100")
            print(f"   Investigation Required: {'✅ Yes' if result.investigation_required else '❌ No'}")
            print(f"   Processing Time: {result.processing_time:.2f}s")
            
            if result.mitre_mapping.techniques:
                print(f"   MITRE Techniques: {', '.join(result.mitre_mapping.techniques)}")
            
            if result.recommendations:
                print(f"   Recommendations:")
                for rec in result.recommendations:
                    print(f"     • {rec}")
        
        
        
        # Generate incident summaries
        print("\n📝 Generating incident summaries...")
        try:
            summary_files = orchestrator.generate_incident_summaries()
            if summary_files:
                print(f"📄 Generated {len(summary_files)} incident summaries:")
                for summary_file in summary_files:
                    print(f"   • {summary_file}")
            else:
                print("   No summaries generated")
        except Exception as e:
            print(f"   ⚠️  Warning: Could not generate summaries: {e}")
        
        # Generate incident JSONs
        print("\n📋 Generating incident JSONs...")
        try:
            incident_files = orchestrator.generate_incident_jsons()
            if incident_files:
                print(f"📄 Generated {len(incident_files)} incident JSONs:")
                for incident_file in incident_files:
                    print(f"   • {incident_file}")
            else:
                print("   No incident JSONs generated")
        except Exception as e:
            print(f"   ⚠️  Warning: Could not generate incident JSONs: {e}")
        
        # Check isolation log
        print("\n🔒 Checking device isolation...")
        try:
            isolation_entries = orchestrator.device_isolation.get_current_session_entries()
            if isolation_entries:
                print(f"🚨 {len(isolation_entries)} device(s) isolated:")
                for entry in isolation_entries:
                    print(f"   • {entry}")
            else:
                print("   No devices isolated")
        except Exception as e:
            print(f"   ⚠️  Warning: Could not check isolation log: {e}")
        
        print("\n✅ SOAR processing completed successfully!")
        return 0
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No arguments - show usage
        print("🔒 SOAR Security Orchestration System")
        print("=" * 50)
        print("\n❌ Error: No alert files specified")
        print("\n📋 Usage:")
        print("   python main.py <alert_file1> [alert_file2] ...")
        print("\n📝 Examples:")
        print("   python main.py SOAR_Samples/alerts/sentinel.json")
        print("   python main.py SOAR_Samples/alerts/sentinel.json SOAR_Samples/alerts/sumologic.json")
        print("\n📁 Sample alerts available:")
        print("   • SOAR_Samples/alerts/sentinel.json")
        print("   • SOAR_Samples/alerts/sumologic.json")
        sys.exit(1)
    else:
        # Run with arguments
        sys.exit(main())
