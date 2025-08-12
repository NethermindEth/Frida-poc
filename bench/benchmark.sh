#!/bin/bash
set -e
cd "$(dirname "$0")/.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p bench/results

echo -e "${BLUE}Frida Comprehensive Benchmark Suite${NC}"
echo "===================================="

# Function to display usage
usage() {
    echo "Usage: $0 [BENCHMARK_TYPE] [COMMAND] [OPTIONS]"
    echo ""
    echo "Benchmark Types:"
    echo "  frida           Traditional FRI benchmarking (commitment + proof + verification)"
    echo "  single-frida    Single proof size and time analysis"
    echo "  defrida         Distributed deFRIDA workflow benchmarking"
    echo ""
    echo "Commands:"
    echo "  full            Run comprehensive benchmark suite"
    echo "  custom          Run custom benchmark with specified parameters"
    echo "  help            Show this help message"
    echo ""
    echo "Common Options:"
    echo "  --output FILE   Output CSV file (default varies by benchmark type)"
    echo ""
    echo "Frida Custom Options:"
    echo "  --blowup-factor N           Blowup factor (required)"
    echo "  --folding-factor N          Folding factor (required)"
    echo "  --max-remainder-degree N    Maximum remainder degree (required)"
    echo "  --data-size N               Data size in bytes (required)"
    echo "  --batch-size N              Batch size (default: 1)"
    echo "  --num-queries N             Number of queries (default: 32)"
    echo ""
    echo "Single-Frida Custom Options:"
    echo "  --blowup-factor N           Blowup factor (required)"
    echo "  --folding-factor N          Folding factor (required)"
    echo "  --max-remainder-degree N    Maximum remainder degree (required)"
    echo "  --data-size N               Data size in bytes (required)"
    echo "  --batch-size N              Batch size (default: 1)"
    echo ""
    echo "deFRIDA Custom Options:"
    echo "  --blowup-factor N           Blowup factor (required)"
    echo "  --folding-factor N          Folding factor (required)"
    echo "  --max-remainder-degree N    Maximum remainder degree (required)"
    echo "  --data-size N               Data size in bytes (required)"
    echo "  --num-validators N          Number of validators (required)"
    echo "  --num-queries N             Number of queries (required)"
    echo "  --batch-size N              Batch size (default: 1)"
    echo ""
    echo "Examples:"
    echo "  $0 frida full"
    echo "  $0 frida custom --blowup-factor 8 --folding-factor 4 --max-remainder-degree 31 --data-size 65536"
    echo "  $0 single-frida full --output my_single_results.csv"
    echo "  $0 single-frida custom --blowup-factor 4 --folding-factor 2 --max-remainder-degree 15 --data-size 32768 --batch-size 8"
    echo "  $0 defrida full"
    echo "  $0 defrida custom --blowup-factor 8 --folding-factor 4 --max-remainder-degree 31 --data-size 65536 --num-validators 16 --num-queries 64"
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
BENCHMARK_TYPE=""
COMMAND=""
ARGS=()

# First argument should be benchmark type
if [[ $# -gt 0 ]]; then
    case $1 in
        frida|single-frida|defrida|help)
            BENCHMARK_TYPE="$1"
            shift
            ;;
        *)
            echo -e "${RED}Error: Invalid benchmark type '$1'${NC}"
            echo ""
            usage
            exit 1
            ;;
    esac
fi

# Second argument should be command
if [[ $# -gt 0 && "$BENCHMARK_TYPE" != "help" ]]; then
    case $1 in
        full|custom)
            COMMAND="$1"
            shift
            ;;
        *)
            echo -e "${RED}Error: Invalid command '$1'${NC}"
            echo ""
            usage
            exit 1
            ;;
    esac
fi

# Remaining arguments are options
ARGS=("$@")

# Handle commands
case $BENCHMARK_TYPE in
    "help")
        usage
        exit 0
        ;;
    "frida")
        build_benchmark
        case $COMMAND in
            "full")
                echo -e "${BLUE}Running full Frida benchmark suite...${NC}"
                echo "This benchmarks traditional FRI proof generation and verification across multiple configurations."
                echo "Estimated time: 15-45 minutes depending on your hardware."
                ./target/release/frida-bench frida $COMMAND "${ARGS[@]}"
                ;;
            "custom")
                echo -e "${BLUE}Running custom Frida benchmark...${NC}"
                ./target/release/frida-bench frida $COMMAND "${ARGS[@]}"
                ;;
            *)
                echo -e "${RED}Error: Missing or invalid command for frida benchmark${NC}"
                usage
                exit 1
                ;;
        esac
        ;;
    "single-frida")
        build_benchmark
        case $COMMAND in
            "full")
                echo -e "${BLUE}Running full Single Frida benchmark suite...${NC}"
                echo "This benchmarks single proof generation time and size with total size estimates."
                echo "Estimated time: 10-30 minutes depending on your hardware."
                ./target/release/frida-bench single-frida $COMMAND "${ARGS[@]}"
                ;;
            "custom")
                echo -e "${BLUE}Running custom Single Frida benchmark...${NC}"
                ./target/release/frida-bench single-frida $COMMAND "${ARGS[@]}"
                ;;
            *)
                echo -e "${RED}Error: Missing or invalid command for single-frida benchmark${NC}"
                usage
                exit 1
                ;;
        esac
        ;;
    "defrida")
        build_benchmark
        case $COMMAND in
            "full")
                echo -e "${BLUE}Running full deFRIDA benchmark suite...${NC}"
                echo "This benchmarks the distributed deFRIDA workflow with validator assignments."
                echo "Estimated time: 20-60 minutes depending on your hardware."
                ./target/release/frida-bench defrida $COMMAND "${ARGS[@]}"
                ;;
            "custom")
                echo -e "${BLUE}Running custom deFRIDA benchmark...${NC}"
                ./target/release/frida-bench defrida $COMMAND "${ARGS[@]}"
                ;;
            *)
                echo -e "${RED}Error: Missing or invalid command for defrida benchmark${NC}"
                usage
                exit 1
                ;;
        esac
        ;;
    *)
        echo -e "${RED}Error: Missing benchmark type${NC}"
        echo ""
        usage
        exit 1
        ;;
esac

echo -e "${GREEN}Benchmark completed successfully!${NC}"