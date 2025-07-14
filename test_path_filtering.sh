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
sudo ./src/dirt -p /tmp/test_paths.txt -V &
DIRT_PID=$!

# Wait for it to start
sleep 3

echo "Creating test files..."
echo "1. Creating file in /mnt/ (should be allowed):"
touch /mnt/testfile1

echo "2. Creating file in /tmp/test (should be allowed):"
mkdir -p /tmp/test
touch /tmp/test/testfile2

echo "3. Creating file in /tmp/other (should be blocked):"
touch /tmp/other/testfile3

echo "4. Creating file in /home (should be blocked):"
touch /home/testfile4

# Wait a moment for events to be processed
sleep 2

echo "Stopping dirt..."
sudo kill $DIRT_PID
wait $DIRT_PID 2>/dev/null

echo "Test completed. Check the output above for events."
echo "Files in /mnt/ and /tmp/test should show up, others should be filtered out."

# Cleanup
rm -f /tmp/test_paths.txt
rm -f /mnt/testfile1
rm -f /tmp/test/testfile2
rm -f /tmp/other/testfile3
rm -f /home/testfile4
rmdir /tmp/test 2>/dev/null
rmdir /tmp/other 2>/dev/null 