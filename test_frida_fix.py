#!/usr/bin/env python3
"""
Test script to verify Frida connection fixes
"""

import asyncio
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from services.frida_service import frida_service


async def test_frida_connection():
    """Test Frida connection and device enumeration"""

    print("=" * 60)
    print("Testing Frida Connection Fixes")
    print("=" * 60)

    # Test 1: Preflight check
    print("\n[1/4] Running preflight check...")
    try:
        result = await frida_service.preflight_check()
        print(f"✓ Frida installed: {result['frida_installed']}")
        print(f"✓ Frida version: {result.get('frida_version', 'N/A')}")
        print(f"✓ Frida devices found: {len(result.get('devices', []))}")
        print(f"✓ ADB devices found: {len(result.get('adb_devices', []))}")

        for dev in result.get('devices', []):
            print(f"  - {dev['id']} ({dev['name']}, type={dev['type']})")
    except Exception as e:
        print(f"✗ Preflight check failed: {e}")

    # Test 2: List devices
    print("\n[2/4] Listing Frida devices...")
    try:
        devices = await frida_service.list_devices()
        print(f"✓ Found {len(devices)} Frida devices")
        for dev in devices:
            print(f"  - {dev['id']} ({dev['name']}, type={dev['type']})")
    except Exception as e:
        print(f"✗ Device enumeration failed: {e}")

    # Test 3: List ADB devices
    print("\n[3/4] Listing ADB devices...")
    try:
        adb_devices = await frida_service.adb_devices()
        print(f"✓ Found {len(adb_devices)} ADB devices")
        for dev in adb_devices:
            print(f"  - {dev['serial']} ({dev['model']}, state={dev['state']})")
    except Exception as e:
        print(f"✗ ADB device enumeration failed: {e}")

    # Test 4: List processes (if device available)
    print("\n[4/4] Listing processes (if device available)...")
    try:
        devices = await frida_service.list_devices()
        if devices:
            device_id = devices[0]['id']
            print(f"  Using device: {device_id}")
            processes = await frida_service.list_processes(device_id)
            print(f"✓ Found {len(processes)} processes")
            # Show first 10 processes
            for proc in processes[:10]:
                print(f"  - PID {proc['pid']}: {proc['name']}")
            if len(processes) > 10:
                print(f"  ... and {len(processes) - 10} more")
        else:
            print("  No Frida devices available, skipping process list")
    except Exception as e:
        print(f"✗ Process enumeration failed: {e}")

    print("\n" + "=" * 60)
    print("Test completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_frida_connection())