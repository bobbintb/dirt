#!/bin/bash

# Test script for dirt path filtering
# This script helps verify that the path filtering feature is working correctly

echo "=== Dirt Path Filtering Test ==="
echo

# Create test files
echo "Creating test files..."
mkdir -p /tmp/dirt_test
echo "test content" > /tmp/dirt_test/file1.txt
echo "test content" > /tmp/dirt_test/file2.txt
echo "test content" > /tmp/test_file.txt
echo "test content" > /etc/test_file.txt

# Create allowed paths file
echo "Creating allowed paths file..."
cat > /tmp/allowed_paths.txt << EOF
# Test allowed paths
/tmp/dirt_test
/etc/test_file.txt
EOF

echo "Allowed paths file contents:"
cat /tmp/allowed_paths.txt
echo

# Test 1: Run dirt with path filtering
echo "=== Test 1: Running dirt with path filtering ==="
echo "This should only show events for /tmp/dirt_test and /etc/test_file.txt"
echo "Press Ctrl+C to stop after a few seconds..."
echo

# Start dirt in background
sudo ./src/dirt -p /tmp/allowed_paths.txt -V &
DIRT_PID=$!

# Wait a moment for dirt to start
sleep 2

# Generate some file events
echo "Generating file events..."
touch /tmp/dirt_test/file3.txt
rm /tmp/dirt_test/file1.txt
echo "new content" >> /tmp/dirt_test/file2.txt

touch /tmp/test_file.txt
rm /tmp/test_file.txt

touch /etc/test_file.txt
echo "new content" >> /etc/test_file.txt

# Wait a bit more
sleep 3

# Stop dirt
echo "Stopping dirt..."
sudo kill $DIRT_PID
wait $DIRT_PID 2>/dev/null

echo
echo "=== Test 2: Running dirt without path filtering ==="
echo "This should show ALL file events"
echo "Press Ctrl+C to stop after a few seconds..."
echo

# Start dirt without filtering
sudo ./src/dirt -V &
DIRT_PID=$!

# Wait a moment for dirt to start
sleep 2

# Generate some file events
echo "Generating file events..."
touch /tmp/dirt_test/file4.txt
rm /tmp/dirt_test/file2.txt
echo "new content" >> /tmp/dirt_test/file3.txt

touch /tmp/test_file.txt
rm /tmp/test_file.txt

# Wait a bit more
sleep 3

# Stop dirt
echo "Stopping dirt..."
sudo kill $DIRT_PID
wait $DIRT_PID 2>/dev/null

# Cleanup
echo
echo "Cleaning up test files..."
rm -rf /tmp/dirt_test
rm -f /tmp/test_file.txt
rm -f /etc/test_file.txt
rm -f /tmp/allowed_paths.txt

echo
echo "=== Test Complete ==="
echo "Compare the output from both tests."
echo "Test 1 should show fewer events (only from allowed paths)."
echo "Test 2 should show all events." 