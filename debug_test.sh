#!/bin/bash

echo "=== Debug Test for Path Filtering ==="
echo

# Create a simple paths file
echo "Creating test paths file..."
cat > /tmp/debug_paths.txt << EOF
/etc/passwd
/tmp/test
EOF

echo "Paths file contents:"
cat /tmp/debug_paths.txt
echo

# Test 1: Run with verbose output to see what's loaded
echo "=== Test 1: Check if paths are loaded ==="
sudo ./src/dirt -p /tmp/debug_paths.txt -V &
DIRT_PID=$!
sleep 2
sudo kill $DIRT_PID
wait $DIRT_PID 2>/dev/null

echo
echo "=== Test 2: Check debug output ==="
echo "Run this in another terminal:"
echo "sudo cat /sys/kernel/debug/tracing/trace_pipe"
echo
echo "Then run:"
echo "sudo ./src/dirt -p /tmp/debug_paths.txt -V -D '*'"
echo
echo "And in a third terminal, try:"
echo "touch /etc/passwd"
echo "touch /tmp/test"
echo "touch /tmp/other"
echo

# Cleanup
rm -f /tmp/debug_paths.txt 