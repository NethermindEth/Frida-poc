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
mkdir -p bench/defrida/results

echo -e "${BLUE}deFRIDA Benchmark Suite${NC}"
echo "========================="

# Function to display usage
usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  full                    Run comprehensive benchmark suite"
    echo "  custom                  Run custom benchmark with specified parameters"
    echo "  help                    Show this help message"
    echo ""
    echo "Full benchmark options:"
    echo "  --output FILE           Output CSV file (default: bench/defrida/results/full_results.csv)"
    echo ""
    echo "Custom benchmark options:"
    echo "  --blowup-factor N       Blowup factor (required)"
    echo "  --folding-factor N      Folding factor (required)"
    echo "  --max-remainder-degree N Maximum remainder degree (required)"
    echo "  --data-size N           Data size in bytes (required)"
    echo "  --num-validators N      Number of validators (required)"
    echo "  --num-queries N         Number of queries (required)"
    echo "  --batch                 Enable batch mode"
    echo "  --output FILE           Output CSV file (default: bench/defrida/results/custom_results.csv)"
    echo ""
    echo "Examples:"
    echo "  $0 full"
    echo "  $0 full --output my_results.csv"
    echo "  $0 custom --blowup-factor 8 --folding-factor 4 --max-remainder-degree 31 --data-size 65536 --num-validators 16 --num-queries 64"
    echo "  $0 custom --blowup-factor 4 --folding-factor 2 --max-remainder-degree 15 --data-size 32768 --num-validators 8 --num-queries 32 --batch"
}

# Build the benchmark binary
build_benchmark() {
    echo -e "${YELLOW}Building deFRIDA benchmark binary...${NC}"
    cargo build --bin defrida-bench --release --features "bench" --quiet
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
        echo -e "${BLUE}Running full benchmark suite...${NC}"
        echo "This may take several minutes depending on your hardware."
        ./target/release/defrida-bench full "${ARGS[@]}"
        ;;
    "custom")
        build_benchmark
        echo -e "${BLUE}Running custom benchmark...${NC}"
        ./target/release/defrida-bench custom "${ARGS[@]}"
        ;;
    *)
        echo -e "${RED}Error: Invalid or missing command${NC}"
        echo ""
        usage
        exit 1
        ;;
esac

echo -e "${GREEN}Benchmark completed successfully!${NC}"