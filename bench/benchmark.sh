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
    echo "Common Custom Options:"
    echo "  --fri-options \"(B,F,R),(B,F,R),...\"   One or more FRI option tuples (blowup, folding, remainder)."
    echo "                                          Example: --fri-options \"(2,2,0),(4,2,3)\""
    echo "  --blowup-factor B                 Blowup factor (shorthand, combined with folding/remainder)."
    echo "  --folding-factor F                Folding factor (shorthand, combined with blowup/remainder)."
    echo "  --max-remainder-degree R          Max remainder degree (shorthand, combined with blowup/folding)."
    echo "  --data-size N,N,...               Comma-separated list of data sizes in bytes."
    echo "  --batch-size N,N,...              Comma-separated list of batch sizes."
    echo "  --field [f64|f128|both]           Field type to run benchmarks on (default: both)."
    echo "  --output FILE                     Output CSV file (default varies by benchmark type)."
    echo ""
    echo "Benchmark-Specific Options:"
    echo "  frida:"
    echo "    --num-queries N,N,...           Comma-separated list of query counts."
    echo "  defrida:"
    echo "    --num-validators N,N,...        Comma-separated list of validator counts."
    echo "    --num-queries N,N,...           Comma-separated list of query counts."
    echo ""
    echo "Examples:"
    echo "  $0 frida full"
    echo "  $0 frida custom --blowup-factor 8 --folding-factor 4 --max-remainder-degree 31 --data-size 65536"
    echo "  $0 frida custom --fri-options \"(8,4,31),(4,2,15)\" --data-size 65536,131072 --field f128"
    echo "  $0 single-frida custom --fri-options \"(4,2,15)\" --batch-size 8,16"
    echo "  $0 defrida custom --fri-options \"(8,4,31)\" --num-validators 16,32 --num-queries 64"
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

# Translate --blowup-factor, --folding-factor, --max-remainder-degree into --fri-options "(B,F,R)".
# If any of the three shorthand flags are present, they are removed from ARGS and replaced
# with a single --fri-options "(B,F,R)" entry (using defaults 2,2,0 for any omitted value).
translate_fri_args() {
    local blowup=""
    local folding=""
    local remainder=""
    local out=()
    local i=0

    while [[ $i -lt ${#ARGS[@]} ]]; do
        case "${ARGS[$i]}" in
            --blowup-factor)
                i=$((i+1)); blowup="${ARGS[$i]}"
                ;;
            --folding-factor)
                i=$((i+1)); folding="${ARGS[$i]}"
                ;;
            --max-remainder-degree)
                i=$((i+1)); remainder="${ARGS[$i]}"
                ;;
            *)
                out+=("${ARGS[$i]}")
                ;;
        esac
        i=$((i+1))
    done

    # If any shorthand flag was provided, build the --fri-options tuple
    if [[ -n "$blowup" || -n "$folding" || -n "$remainder" ]]; then
        blowup="${blowup:-2}"
        folding="${folding:-2}"
        remainder="${remainder:-0}"
        out+=("--fri-options" "(${blowup},${folding},${remainder})")
    fi

    ARGS=("${out[@]}")
}

# Map full/custom to the correct binary flag or subcommand
get_bench_cmd() {
    if [ "$COMMAND" = "full" ]; then
        echo "--full"
    else
        echo "custom"
    fi
}

# Handle commands
case $BENCHMARK_TYPE in
    "help")
        usage
        exit 0
        ;;
    "frida")
        build_benchmark
        translate_fri_args
        case $COMMAND in
            "full")
                echo -e "${BLUE}Running full Frida benchmark suite...${NC}"
                echo "This benchmarks traditional FRI proof generation and verification across multiple configurations."
                echo "Estimated time: 15-45 minutes depending on your hardware."
                ./target/release/frida-bench frida $(get_bench_cmd) "${ARGS[@]}"
                ;;
            "custom")
                echo -e "${BLUE}Running custom Frida benchmark...${NC}"
                ./target/release/frida-bench frida $(get_bench_cmd) "${ARGS[@]}"
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
        translate_fri_args
        case $COMMAND in
            "full")
                echo -e "${BLUE}Running full Single Frida benchmark suite...${NC}"
                echo "This benchmarks single proof generation time and size with total size estimates."
                echo "Estimated time: 10-30 minutes depending on your hardware."
                ./target/release/frida-bench single-frida $(get_bench_cmd) "${ARGS[@]}"
                ;;
            "custom")
                echo -e "${BLUE}Running custom Single Frida benchmark...${NC}"
                ./target/release/frida-bench single-frida $(get_bench_cmd) "${ARGS[@]}"
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
        translate_fri_args
        case $COMMAND in
            "full")
                echo -e "${BLUE}Running full deFRIDA benchmark suite...${NC}"
                echo "This benchmarks the distributed deFRIDA workflow with validator assignments."
                echo "Estimated time: 20-60 minutes depending on your hardware."
                ./target/release/frida-bench defrida $(get_bench_cmd) "${ARGS[@]}"
                ;;
            "custom")
                echo -e "${BLUE}Running custom deFRIDA benchmark...${NC}"
                ./target/release/frida-bench defrida $(get_bench_cmd) "${ARGS[@]}"
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