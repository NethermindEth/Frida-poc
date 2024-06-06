#!/bin/bash
mkdir -p ./logs
bash setup.sh
go build -o eigen_benchmark
for threads in 1 2 4 8; do
    echo "Running... Threads: $threads";
    ./eigen_benchmark $threads &> ./logs/threads_$threads.txt;
done
