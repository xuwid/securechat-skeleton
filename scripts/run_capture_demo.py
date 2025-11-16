#!/usr/bin/env python3
"""
Automated demo for Wireshark capture
Starts server, runs automated client session, captures traffic
"""
import subprocess
import time
import sys
import signal
import os

def main():
    print("🔍 Starting Automated Wireshark Capture Demo")
    print("=" * 50)
    
    # Start tcpdump in background
    print("\n1️⃣ Starting packet capture...")
    tcpdump_proc = subprocess.Popen(
        ['sudo', 'tcpdump', '-i', 'lo', '-w', 'securechat_demo.pcap', 'tcp port 5555'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)
    print("   ✅ Packet capture started (PID: {})".format(tcpdump_proc.pid))
    
    # Start server
    print("\n2️⃣ Starting SecureChat server...")
    server_proc = subprocess.Popen(
        ['python3', 'app/server.py'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    print("   ✅ Server started (PID: {})".format(server_proc.pid))
    
    # Note: Actual client automation requires interactive input handling
    print("\n3️⃣ Server is ready for client connections")
    print("\n" + "=" * 50)
    print("📝 NEXT STEPS:")
    print("   1. In another terminal, run: python3 app/client.py")
    print("   2. Register/Login with a user")
    print("   3. Send a few messages")
    print("   4. Type 'quit' to exit client")
    print("   5. Press Ctrl+C here to stop capture")
    print("=" * 50)
    
    try:
        # Wait for user to complete demo
        signal.pause()
    except KeyboardInterrupt:
        print("\n\n4️⃣ Stopping all processes...")
        
        # Stop server
        server_proc.terminate()
        server_proc.wait(timeout=5)
        print("   ✅ Server stopped")
        
        # Stop tcpdump
        tcpdump_proc.terminate()
        tcpdump_proc.wait(timeout=5)
        print("   ✅ Packet capture stopped")
        
        # Check if capture file was created
        if os.path.exists('securechat_demo.pcap'):
            size = os.path.getsize('securechat_demo.pcap')
            print(f"\n✅ Capture saved: securechat_demo.pcap ({size} bytes)")
            print("\n📊 To analyze:")
            print("   wireshark securechat_demo.pcap")
            print("   OR")
            print("   tcpdump -r securechat_demo.pcap -n | head -50")
        else:
            print("\n⚠️  No capture file found")
        
        print("\n✅ Demo complete!")

if __name__ == '__main__':
    main()
