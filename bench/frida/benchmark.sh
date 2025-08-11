#!/bin/bash
set -e
cd "$(dirname "$0")/../.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p bench/frida/results

echo -e "${BLUE}Frida Proof Size & Time Benchmark Suite${NC}"
echo "========================================"

# Function to display usage
usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  full                    Run comprehensive Frida benchmark suite"
    echo "  custom                  Run custom benchmark with specified parameters"
    echo "  help                    Show this help message"
    echo ""
    echo "Full benchmark options:"
    echo "  --output FILE           Output CSV file (default: bench/frida/results_full.csv)"
    echo ""
    echo "Custom benchmark options:"
    echo "  --blowup-factor N       Blowup factor (required)"
    echo "  --folding-factor N      Folding factor (required)"
    echo "  --max-remainder-degree N Maximum remainder degree (required)"
    echo "  --data-size N           Data size in bytes (required)"
    echo "  --batch-size N          Batch size (default: 1, use >1 for batched mode)"
    echo "  --output FILE           Output CSV file (default: bench/frida/results_custom.csv)"
    echo ""
    echo "Examples:"
    echo "  $0 full"
    echo "  $0 full --output my_frida_results.csv"
    echo "  $0 custom --blowup-factor 8 --folding-factor 4 --max-remainder-degree 31 --data-size 65536"
    echo "  $0 custom --blowup-factor 4 --folding-factor 2 --max-remainder-degree 15 --data-size 32768 --batch-size 8"
    echo "  $0 custom --blowup-factor 16 --folding-factor 8 --max-remainder-degree 63 --data-size 131072 --batch-size 16 --output large_config.csv"
    echo ""
    echo "Note: This benchmark focuses on single proof generation time and size, then estimates"
    echo "      total proof size as domain_size * single_proof_size for analysis purposes."
}

# Build the benchmark binary
build_benchmark() {
    echo -e "${YELLOW}Building Frida benchmark binary...${NC}"
    cargo build --bin frida-bench --release --features "bench" --quiet
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Build successful${NC}"
    else
        echo -e "${RED}Build failed${NC}"
        exit 1
    fi
}

# Parse command line arguments
COMMAND=""
ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        full|custom|help)
            COMMAND="$1"
            shift
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

# Handle commands
case $COMMAND in
    "help")
        usage
        exit 0
        ;;
    "full")
        build_benchmark
        echo -e "${BLUE}Running full Frida benchmark suite...${NC}"
        echo "This benchmarks proof generation for single positions across various configurations."
        echo "Estimated time: 10-30 minutes depending on your hardware."
        ./target/release/frida-bench full "${ARGS[@]}"
        ;;
    "custom")
        build_benchmark
        echo -e "${BLUE}Running custom Frida benchmark...${NC}"
        ./target/release/frida-bench custom "${ARGS[@]}"
        ;;
    *)
        echo -e "${RED}Error: Invalid or missing command${NC}"
        echo ""
        usage
        exit 1
        ;;
esac

echo -e "${GREEN}Frida benchmark completed successfully!${NC}"