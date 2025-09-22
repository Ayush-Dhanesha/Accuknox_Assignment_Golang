#!/bin/bash

echo "🔨 Building Process-Specific eBPF Filter"
echo "========================================"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo "📋 Objective: Allow 'myprocess' ONLY on port 4040, block on other ports"
echo ""

# Build the eBPF program
echo -e "${BLUE}Building eBPF program...${NC}"
clang -target bpf -O2 -g -c process_filter.c -o process_filter.o

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ eBPF program compiled successfully${NC}"
    ls -la process_filter.o
else
    echo -e "${RED}❌ eBPF compilation failed${NC}"
    exit 1
fi

# Build the test application
echo -e "\n${BLUE}Building test application...${NC}"
gcc -o test_process test_process.c

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Test application compiled successfully${NC}"
    ls -la test_process
else
    echo -e "${RED}❌ Test application compilation failed${NC}"
    exit 1
fi

echo -e "\n${GREEN}🎉 Build complete!${NC}"
echo -e "${BLUE}Available executables:${NC}"
echo "  - process_filter.o    (eBPF bytecode)"
echo "  - test_process        (Test application)"

echo -e "\n${BLUE}Usage:${NC}"
echo "  ./test_process        # Test the filtering logic"
