#!/bin/bash

echo "=== Testing Path Filtering ==="
echo

# Create test paths file
echo "Creating test paths file..."
cat > /tmp/test_paths.txt << EOF
/mnt/
/tmp/test
EOF

echo "Paths file contents:"
cat /tmp/test_paths.txt
echo

# Start dirt in background
echo "Starting dirt with path filtering..."
sudo ./bin/dirt -p /tmp/test_paths.txt -V &
DIRT_PID=$!

# Wait for it to start
sleep 3

echo "Creating test files..."
echo "1. Creating file in /mnt/ (should be allowed):"
sudo touch /mnt/testfile1

echo "2. Creating file in /tmp/test (should be allowed):"
sudo mkdir -p /tmp/test
sudo touch /tmp/test/testfile2

echo "3. Creating file in /tmp/other (should be blocked):"
sudo mkdir -p /tmp/other
sudo touch /tmp/other/testfile3

echo "4. Creating file in /home (should be blocked):"
sudo touch /home/testfile4

# Wait a moment for events to be processed
sleep 2

echo "Stopping dirt..."
sudo kill $DIRT_PID
wait $DIRT_PID 2>/dev/null

echo "Test completed. Check the output above for events."
echo "Files in /mnt/ and /tmp/test should show up, others should be filtered out."

# Cleanup
sudo rm -f /tmp/test_paths.txt
sudo rm -f /mnt/testfile1
sudo rm -f /tmp/test/testfile2
sudo rm -f /tmp/other/testfile3
sudo rm -f /home/testfile4
sudo rmdir /tmp/test 2>/dev/null
sudo rmdir /tmp/other 2>/dev/null