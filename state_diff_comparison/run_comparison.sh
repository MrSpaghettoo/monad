#!/bin/bash

echo "Starting Monad State Diff Comparison"
echo "===================================="

if [ ! -f "../failblock.log" ]; then
    echo "Error: failblock.log not found. Please ensure Monad has generated the log file."
    exit 1
fi

echo ""
echo "Running full comparison..."
echo "=========================="

python compare_monad_state_diffs.py $RPC_URL

echo ""
echo "Comparison completed. Check the generated JSON file for detailed results."
