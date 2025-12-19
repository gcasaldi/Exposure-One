#!/bin/bash

# Exposure One - Test Script
# Script per testare rapidamente l'installazione e le funzionalità

echo "🎯 Exposure One - Test Suite"
echo "======================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if server is running
echo "📡 Checking if server is running..."
if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Server is running${NC}"
else
    echo -e "${RED}✗ Server is not running${NC}"
    echo "Please start the server with: python main.py"
    exit 1
fi

echo ""

# Test health endpoint
echo "🏥 Testing health endpoint..."
HEALTH=$(curl -s http://localhost:8000/api/health)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Health check passed${NC}"
    echo "$HEALTH" | jq '.' 2>/dev/null || echo "$HEALTH"
else
    echo -e "${RED}✗ Health check failed${NC}"
fi

echo ""

# Test scan with a public domain
echo "🔍 Testing scan with example.com..."
echo "This may take 10-20 seconds..."

SCAN_RESULT=$(curl -s -X POST http://localhost:8000/api/scan \
    -H "Content-Type: application/json" \
    -d '{"target": "example.com"}')

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Scan completed successfully${NC}"
    echo ""
    echo "📊 Results Summary:"
    echo "$SCAN_RESULT" | jq '{
        target: .target,
        exposure_score: .risk_score.total_score,
        risk_level: .risk_score.risk_level,
        scan_duration: .scan_duration,
        total_findings: .technical_view.total_findings
    }' 2>/dev/null || echo "$SCAN_RESULT"
else
    echo -e "${RED}✗ Scan failed${NC}"
fi

echo ""
echo "======================================"
echo "✅ Test completed!"
echo ""
echo "Next steps:"
echo "  - Open browser: http://localhost:8000"
echo "  - View API docs: http://localhost:8000/docs"
echo "  - Run custom scan: curl -X POST http://localhost:8000/api/scan -H 'Content-Type: application/json' -d '{\"target\": \"your-domain.com\"}'"
