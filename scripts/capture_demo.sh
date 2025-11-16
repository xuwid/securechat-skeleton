#!/bin/bash
# Wireshark Capture Script for SecureChat Demo
# This script captures network traffic during a SecureChat session demonstration

CAPTURE_FILE="securechat_demo.pcap"
PORT=5555
INTERFACE="lo"

echo "🔍 SecureChat Wireshark Capture Demo"
echo "======================================"
echo ""
echo "This script will:"
echo "1. Start packet capture on localhost:$PORT"
echo "2. Wait for you to demonstrate the SecureChat system"
echo "3. Save the capture to $CAPTURE_FILE"
echo ""
echo "INSTRUCTIONS:"
echo "-------------"
echo "1. Press ENTER to start capturing"
echo "2. In another terminal, start the server: python3 app/server.py"
echo "3. In a third terminal, start the client: python3 app/client.py"
echo "4. Perform a chat session (register/login, send messages)"
echo "5. Close the client and server"
echo "6. Press Ctrl+C in this terminal to stop capturing"
echo ""
read -p "Press ENTER to start capturing traffic..."

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  This script needs sudo privileges to capture packets."
    echo "Restarting with sudo..."
    sudo "$0" "$@"
    exit $?
fi

echo ""
echo "✅ Starting packet capture on $INTERFACE port $PORT..."
echo "📦 Capture file: $CAPTURE_FILE"
echo ""
echo "🔴 RECORDING... (Press Ctrl+C when done)"
echo ""

# Start tcpdump
tcpdump -i "$INTERFACE" -w "$CAPTURE_FILE" "tcp port $PORT" -v

echo ""
echo "✅ Capture complete! Saved to: $CAPTURE_FILE"
echo ""
echo "📊 ANALYSIS:"
echo "------------"

# Show capture statistics
if [ -f "$CAPTURE_FILE" ]; then
    echo "File size: $(du -h "$CAPTURE_FILE" | cut -f1)"
    echo ""
    echo "To analyze the capture in Wireshark:"
    echo "  wireshark $CAPTURE_FILE"
    echo ""
    echo "To view capture summary:"
    echo "  tcpdump -r $CAPTURE_FILE -n | head -50"
    echo ""
    echo "To filter only encrypted chat messages:"
    echo "  tcpdump -r $CAPTURE_FILE -n 'tcp port $PORT' -A | grep -A 5 'CHAT_MSG'"
    echo ""
    echo "✅ You can now use this .pcap file in your submission!"
fi
