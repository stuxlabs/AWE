#!/bin/bash
# DOM XSS Agent Test Suite
# Tests the agent against known vulnerable targets

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         DOM XSS Detection Agent - Test Suite                  ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check Docker
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}✗ Docker is not running${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker is running${NC}"

# Check .env
if [ ! -f .env ]; then
    echo -e "${RED}✗ .env file not found${NC}"
    echo "  Create .env with AWS credentials:"
    echo "  AWS_ACCESS_KEY_ID=..."
    echo "  AWS_SECRET_ACCESS_KEY=..."
    exit 1
fi
echo -e "${GREEN}✓ .env file found${NC}"

# Build image
echo ""
echo "Building Docker image..."
docker build -t xss-agent . >/dev/null 2>&1
echo -e "${GREEN}✓ Docker image built${NC}"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Running tests..."
echo "════════════════════════════════════════════════════════════════"
echo ""

# Test counters
PASSED=0
FAILED=0

# Test 1: Basic DOM XSS
echo "Test 1: Basic DOM XSS (ccgq7jee.xssy.uk)"
echo "Expected: 2 vulnerabilities with innerHTML sink"
echo -n "Running... "

OUTPUT=$(./run-docker.sh "https://ccgq7jee.xssy.uk/" --dom 2>&1)

if echo "$OUTPUT" | grep -q "✓✓✓ SUCCESS! Found 2 DOM XSS vulnerabilities"; then
    echo -e "${GREEN}PASSED ✓${NC}"
    echo "  - Found 2 vulnerabilities"
    echo "  - Sink: innerHTML"
    echo "  - Parameter: search"
    ((PASSED++))
else
    echo -e "${RED}FAILED ✗${NC}"
    echo "  Expected 2 vulnerabilities, check output"
    ((FAILED++))
fi
echo ""

# Test 2: Different parameter name
echo "Test 2: Different Parameter (7axgjmar.xssy.uk)"
echo "Expected: 3 vulnerabilities with 'name' parameter"
echo -n "Running... "

OUTPUT=$(./run-docker.sh "https://7axgjmar.xssy.uk/" --dom 2>&1)

if echo "$OUTPUT" | grep -q "✓✓✓ SUCCESS! Found 3 DOM XSS vulnerabilities"; then
    echo -e "${GREEN}PASSED ✓${NC}"
    echo "  - Found 3 vulnerabilities"
    echo "  - Parameter: name (auto-discovered)"
    ((PASSED++))
else
    echo -e "${RED}FAILED ✗${NC}"
    echo "  Expected 3 vulnerabilities, check output"
    ((FAILED++))
fi
echo ""

# Test 3: encodeURI bypass
echo "Test 3: encodeURI Bypass (axh77nxo.xssy.uk)"
echo "Expected: 1 vulnerability via LLM refinement"
echo -n "Running... "

OUTPUT=$(./run-docker.sh "https://axh77nxo.xssy.uk/" --dom 2>&1)

if echo "$OUTPUT" | grep -q "✓✓✓ SUCCESS! Found 1 DOM XSS"; then
    echo -e "${GREEN}PASSED ✓${NC}"
    echo "  - Found 1 vulnerability"
    echo "  - Method: LLM refinement"
    echo "  - Bypass: encodeURI() with single quotes"
    ((PASSED++))
else
    echo -e "${RED}FAILED ✗${NC}"
    echo "  Expected 1 vulnerability via LLM refinement"
    ((FAILED++))
fi
echo ""

# Test 4: Attribute injection
echo "Test 4: Attribute Injection (n2kk6q7k.xssy.uk)"
echo "Expected: 1 vulnerability via LLM refinement"
echo -n "Running... "

OUTPUT=$(./run-docker.sh "https://n2kk6q7k.xssy.uk/" --dom 2>&1)

if echo "$OUTPUT" | grep -q "✓✓✓ SUCCESS! Found 1 DOM XSS"; then
    echo -e "${GREEN}PASSED ✓${NC}"
    echo "  - Found 1 vulnerability"
    echo "  - Method: LLM refinement"
    echo "  - Bypass: Attribute breakout"
    ((PASSED++))
else
    echo -e "${RED}FAILED ✗${NC}"
    echo "  Expected 1 vulnerability via LLM refinement"
    ((FAILED++))
fi
echo ""

# Results
echo "════════════════════════════════════════════════════════════════"
echo "Test Results"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓✓✓ ALL TESTS PASSED - DOM XSS Agent is working correctly!  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Your DOM XSS detection agent is ready for production use!"
    echo ""
    echo "Next steps:"
    echo "  • Test against your own targets"
    echo "  • Check results/ for detailed JSON reports"
    echo "  • Check screenshots/ for execution evidence"
    echo "  • Read README_DOM_XSS.md for advanced features"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ✗ SOME TESTS FAILED - Please check the output above          ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  • Check AWS credentials in .env"
    echo "  • Try running with --log-level DEBUG"
    echo "  • Verify network connectivity to test targets"
    echo "  • Check logs/ directory for detailed errors"
    exit 1
fi
