package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/Layr-Labs/eigenda/encoding"
	"github.com/Layr-Labs/eigenda/encoding/kzg"
	"github.com/Layr-Labs/eigenda/encoding/kzg/prover"
	"github.com/Layr-Labs/eigenda/encoding/kzg/verifier"
	"github.com/Layr-Labs/eigenda/encoding/utils/codec"
)

var Kb int = 1024
var logs []string

func roundUpDivide(a uint64, b uint64) uint64 {
	return (a + b - 1) / b
}

// Assuming even staking distribution
func calcChunkData(size uint64, operator_count uint64, quorum_threshold uint64, adversary_threshold uint64) (uint64, uint64) {
	maxChunk := roundUpDivide(200*size, (quorum_threshold-adversary_threshold)*operator_count)
	maxChunk2 := roundUpDivide(200*size, (quorum_threshold-adversary_threshold)*8192)
	if maxChunk < maxChunk2 {
		maxChunk = maxChunk2
	}
	maxChunk = encoding.NextPowerOf2(maxChunk)

	chunkLength := uint64(2)
	for {
		numChunks := roundUpDivide(100*size, chunkLength*(quorum_threshold-adversary_threshold))
		if chunkLength > maxChunk {
			return chunkLength / uint64(2), encoding.NextPowerOf2(numChunks)
		}

		if numChunks <= operator_count {
			return chunkLength, encoding.NextPowerOf2(numChunks)
		}

		chunkLength *= 2
	}
}

func test(prover *prover.Prover, verifier *verifier.Verifier, data_size int, operator_count int, runs int) {
	data := make([]byte, data_size)
	rand.Read(data)
	i := runs
	prover_sum := time.Duration(0)
	verifier_sum := time.Duration(0)
	for i > 0 {
		i--
		startTime := time.Now()
		encodedData := codec.ConvertByPaddingEmptyByte(data)
		blobSize := uint64(len(encodedData) / 32)
		chunkLength, numChunks := calcChunkData(blobSize, uint64(operator_count), 100, 50)
		commitments, frames, err := prover.EncodeAndProve(encodedData, encoding.EncodingParams{
			ChunkLength: chunkLength,
			NumChunks:   numChunks,
		})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		prover_sum += time.Since(startTime)

		startTime = time.Now()
		err = verifier.VerifyBlobLength(commitments)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		err = verifier.VerifyCommitEquivalenceBatch([]encoding.BlobCommitments{commitments})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		samples := make([]encoding.Sample, 1)
		for ind, frame := range frames[:1] {
			samples[ind] = encoding.Sample{
				Commitment:      commitments.Commitment,
				Chunk:           frame,
				AssignmentIndex: uint(ind),
				BlobIndex:       0,
			}
		}
		subBatch := encoding.SubBatch{
			Samples:  samples,
			NumBlobs: 1,
		}

		err = verifier.UniversalVerifySubBatch(encoding.EncodingParams{
			ChunkLength: chunkLength,
			NumChunks:   numChunks,
		}, subBatch.Samples, subBatch.NumBlobs)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		verifier_sum += time.Since(startTime)
		fmt.Println()
	}

	logs = append(logs, fmt.Sprintf("Operators: %d, Size: %dKb, Runs: %d, Proving AVG: %v, Verification AVG: %v", operator_count, data_size/Kb, runs, prover_sum/time.Duration(runs), verifier_sum/time.Duration(runs)))
}

func main() {

	threads, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Running... Threads: %d\n", threads)
	runtime.GOMAXPROCS(threads)

	prover, err := prover.NewProver(&kzg.KzgConfig{
		G1Path:          "resources/g1.point",
		G2Path:          "resources/g2.point",
		G2PowerOf2Path:  "resources/g2.point.powerOf2",
		CacheDir:        "resources/cache",
		NumWorker:       uint64(threads),
		SRSOrder:        268435456,
		SRSNumberToLoad: 262144,
		Verbose:         true,
		PreloadEncoder:  true,
	}, true)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	verifier, err := verifier.NewVerifier(&kzg.KzgConfig{
		G1Path:          "resources/g1.point",
		G2PowerOf2Path:  "resources/g2.point.powerOf2",
		CacheDir:        "resources/cache",
		NumWorker:       uint64(runtime.NumCPU()),
		SRSOrder:        268435456,
		SRSNumberToLoad: 262144,
	}, false)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	runs := 10
	operator_counts := []int{1, 2, 16, 32, 64, 128}

	// Making sure the data perfectly fits after padding (31bytes -> 32bytes) to get best results
	data_sizes := []int{124 * Kb, 248 * Kb, 496 * Kb, 992 * Kb, 1984 * Kb}

	for _, operator_count := range operator_counts {
		for _, data_size := range data_sizes {
			fmt.Printf("Operators: %d, Size: %dKb, Runs: %d\n", operator_count, data_size/Kb, runs)
			test(prover, verifier, data_size, operator_count, runs)
		}
	}

	for _, l := range logs {
		fmt.Println(l)
	}
}
