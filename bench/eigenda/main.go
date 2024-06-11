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
	"github.com/Layr-Labs/eigenda/encoding/rs"
	"github.com/Layr-Labs/eigenda/encoding/utils/codec"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var Kb int = 1024
var logs []string
var threads int

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
	convert_sum := time.Duration(0)
	commit_sum := time.Duration(0)
	proof_sum := time.Duration(0)
	verify_sum := time.Duration(0)
	commit_size := 0
	chunk_size := 0
	for i > 0 {
		i--

		// CONVERSION INTO FELTS
		startTime := time.Now()
		encodedData := codec.ConvertByPaddingEmptyByte(data)
		inputFr, err := rs.ToFrArray(encodedData)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		convert_sum += time.Since(startTime)

		// preparation
		blobSize := uint64(len(encodedData) / 32)
		chunkLength, numChunks := calcChunkData(blobSize, uint64(operator_count), 100, 50)
		params := encoding.EncodingParams{
			ChunkLength: chunkLength,
			NumChunks:   numChunks,
		}
		enc, err := prover.GetKzgEncoder(params)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// COMMITMENT GENERATION
		startTime = time.Now()
		polyCoeffs := inputFr
		commit, err := enc.Commit(polyCoeffs)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		config := ecc.MultiExpConfig{}
		var lengthCommitment bn254.G2Affine
		_, err = lengthCommitment.MultiExp(enc.Srs.G2[:len(polyCoeffs)], polyCoeffs, config)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		shiftedSecret := enc.G2Trailing[enc.KzgConfig.SRSNumberToLoad-uint64(len(inputFr)):]
		var lengthProof bn254.G2Affine
		_, err = lengthProof.MultiExp(shiftedSecret, polyCoeffs, config)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		commitments := encoding.BlobCommitments{
			Commitment:       (*encoding.G1Commitment)(&commit),
			LengthCommitment: (*encoding.G2Commitment)(&lengthCommitment),
			LengthProof:      (*encoding.G2Commitment)(&lengthProof),
			Length:           uint(len(polyCoeffs)),
		}
		commit_sum += time.Since(startTime)

		// FRAMING AND PROOF GENERATION
		startTime = time.Now()
		polyEvals, _, err := enc.ExtendPolyEval(polyCoeffs)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		frames, indices, err := enc.MakeFrames(polyEvals)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		paddedCoeffs := make([]fr.Element, enc.NumEvaluations())
		copy(paddedCoeffs, polyCoeffs)
		proofs, err := enc.ProveAllCosetThreads(paddedCoeffs, enc.NumChunks, enc.ChunkLength, enc.NumWorker)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		kzgFrames := make([]*encoding.Frame, len(frames))
		for i, index := range indices {
			kzgFrames[i] = &encoding.Frame{
				Proof:  proofs[index],
				Coeffs: frames[i].Coeffs,
			}
		}
		proof_sum += time.Since(startTime)

		// VERIFICATION OF A SINGLE FRAME
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
		for ind, frame := range kzgFrames[:1] {
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
		verify_sum += time.Since(startTime)
		fmt.Println()

		commit_size = 0
		bytes, _ := commitments.Commitment.Serialize()
		commit_size += len(bytes)
		bytes, _ = commitments.LengthCommitment.Serialize()
		commit_size += len(bytes)
		bytes, _ = commitments.LengthProof.Serialize()
		commit_size += len(bytes)
		// +4 for length
		commit_size += 4

		chunk_size = 0
		chunk_size += len(kzgFrames[0].Coeffs) * 32
		chunk_size += len(kzgFrames[0].Proof.Bytes())
	}

	logs = append(logs, fmt.Sprintf("%d, %d, %dKb, %v, %v, %v, %v, %d, %d", threads, operator_count, data_size/Kb, convert_sum/time.Duration(runs), commit_sum/time.Duration(runs), proof_sum/time.Duration(runs), verify_sum/time.Duration(runs), commit_size, chunk_size))
}

func main() {
	var err error
	threads, err = strconv.Atoi(os.Args[1])
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

	fmt.Println("Threads, Operators, Data Size, Conversion, Commitment, Proofs, Verification, Commitment Size, Chunk Size")
	for _, l := range logs {
		fmt.Println(l)
	}
}
