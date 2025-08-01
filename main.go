package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"unsafe"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
	"google.golang.org/protobuf/proto"
)

// TDReport represents the runtime TD Report structure (584 bytes)
// This is the actual TD Report that contains the runtime RTMR values
// Based on TDX Architecture Specification
type TDReport struct {
	ReportType     [4]byte   // Report type
	Reserved1      [12]byte  // Reserved
	CpuSvn         [16]byte  // CPU SVN
	TeeTcbInfoHash [48]byte  // TEE TCB Info Hash
	TeeInfoHash    [48]byte  // TEE Info Hash
	ReportData     [64]byte  // Report data
	Reserved2      [32]byte  // Reserved
	MacStruct      [256]byte // MAC structure
	TeeTcbSvn      [16]byte  // TEE TCB SVN
	MrSeam         [48]byte  // SEAM measurement
	MrSignerSeam   [48]byte  // SEAM signer measurement
	SeamAttributes [8]byte   // SEAM attributes
	TdAttributes   [8]byte   // TD attributes
	Xfam           [8]byte   // XFAM
	MrTd           [48]byte  // TD measurement
	MrConfigId     [48]byte  // Config ID
	MrOwner        [48]byte  // Owner measurement
	MrOwnerConfig  [48]byte  // Owner config
	Rtmr0          [48]byte  // RTMR 0 - Runtime measurement register 0
	Rtmr1          [48]byte  // RTMR 1 - Runtime measurement register 1
	Rtmr2          [48]byte  // RTMR 2 - Runtime measurement register 2
	Rtmr3          [48]byte  // RTMR 3 - Runtime measurement register 3
	ServTdHash     [48]byte  // Service TD hash
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <quote-file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s quote.bin\n", os.Args[0])
		os.Exit(1)
	}

	quoteFile := os.Args[1]

	fmt.Printf("Reading TDX quote from: %s\n", quoteFile)
	fmt.Println("==============================")

	// Read the quote file
	quoteData, err := os.ReadFile(quoteFile)
	if err != nil {
		log.Fatalf("Failed to read quote file: %v", err)
	}

	fmt.Printf("Quote file size: %d bytes\n\n", len(quoteData))

	// Try to parse as protobuf QuoteV4 first (if it's from GetAttestation)
	var quote tdx.QuoteV4
	if err := proto.Unmarshal(quoteData, &quote); err == nil {
		// It's a protobuf quote
		fmt.Println("Detected protobuf QuoteV4 format")
		extractFromQuoteV4(&quote)
		return
	}

	// Try to parse as raw quote using ABI package
	if quoteProto, err := abi.QuoteToProto(quoteData); err == nil {
		if q4, ok := quoteProto.(*tdx.QuoteV4); ok {
			fmt.Println("Detected raw QuoteV4 format, converted to protobuf")
			extractFromQuoteV4(q4)
			return
		}
	}

	// If ABI parsing failed, try manual raw quote parsing
	fmt.Println("Detected raw quote format, attempting manual parsing...")
	extractFromRawQuote(quoteData)
}

func extractFromQuoteV4(quote *tdx.QuoteV4) {
	// First validate the quote structure
	validateQuoteStructure(quote)
	
	tdQuoteBody := quote.GetTdQuoteBody()
	if tdQuoteBody == nil {
		log.Fatal("No TD Quote Body found in quote")
	}

	// Convert the protobuf TDQuoteBody to our runtime TD Report structure
	tdReport := &TDReport{}
	
	// Copy the RTMR values from the protobuf structure
	rtmrs := tdQuoteBody.GetRtmrs()
	if len(rtmrs) >= 4 {
		copy(tdReport.Rtmr0[:], rtmrs[0])
		copy(tdReport.Rtmr1[:], rtmrs[1])
		copy(tdReport.Rtmr2[:], rtmrs[2])
		copy(tdReport.Rtmr3[:], rtmrs[3])
	}
	
	// Copy other important measurements
	copy(tdReport.MrTd[:], tdQuoteBody.GetMrTd())
	copy(tdReport.MrConfigId[:], tdQuoteBody.GetMrConfigId())
	copy(tdReport.MrOwner[:], tdQuoteBody.GetMrOwner())
	copy(tdReport.MrOwnerConfig[:], tdQuoteBody.GetMrOwnerConfig())

	printRTMRValues(tdReport)
}

func extractFromRawQuote(quoteData []byte) {
	// Use the verify library to parse the raw quote
	// This will validate the quote structure and extract the TD Report
	opts := verify.Options{
		GetCollateral:    false, // Don't fetch collateral for simple extraction
		CheckRevocations: false, // Don't check CRL for simple extraction
	}

	// Parse and verify the quote structure (but not signatures/collateral)
	err := verify.RawTdxQuote(quoteData, &opts)
	if err != nil {
		// If verification fails, try to extract anyway for debugging
		fmt.Printf("Warning: Quote verification failed: %v\n", err)
		fmt.Println("Attempting to extract RTMR values anyway...\n")
	}

	// For raw quote parsing, we need to manually extract the runtime TD Report
	// This contains the actual runtime RTMR values
	tdReport, err := extractTDReportFromRawQuote(quoteData)
	if err != nil {
		log.Fatalf("Failed to extract TD Report from raw quote: %v", err)
	}

	printRTMRValues(tdReport)
}

func extractTDReportFromRawQuote(quoteData []byte) (*TDReport, error) {
	// This extracts the runtime TD Report from the TDX quote
	// TDX Quote v4 structure:
	// - Header (48 bytes)
	// - TD Report (584 bytes) <- This is what we want (the runtime TD Report)
	// - Signature and certificates follow...

	if len(quoteData) < 632 { // 48 + 584
		return nil, fmt.Errorf("quote too short: %d bytes", len(quoteData))
	}

	// Skip header (48 bytes) and extract the actual TD Report (584 bytes)
	tdReportBytes := quoteData[48:632]

	// Parse the raw TD Report bytes into our structure
	// This gives us the runtime RTMR values
	if len(tdReportBytes) != 584 {
		return nil, fmt.Errorf("invalid TD Report size: %d bytes, expected 584", len(tdReportBytes))
	}

	// Cast the bytes directly to our TDReport structure
	// This preserves the exact runtime RTMR values
	tdReport := (*TDReport)(unsafe.Pointer(&tdReportBytes[0]))

	return tdReport, nil
}

func printRTMRValues(tdReport *TDReport) {
	fmt.Println("Runtime TD Report RTMR Values:")
	fmt.Println("==============================")

	// Display all runtime RTMR values from the actual TD Report
	rtmrs := [4][48]byte{tdReport.Rtmr0, tdReport.Rtmr1, tdReport.Rtmr2, tdReport.Rtmr3}
	
	for i, rtmr := range rtmrs {
		// Check if RTMR is all zeros (uninitialized)
		allZeros := true
		for _, b := range rtmr {
			if b != 0 {
				allZeros = false
				break
			}
		}

		if allZeros {
			fmt.Printf("RTMR[%d]: <all zeros - uninitialized>\n", i)
		} else {
			fmt.Printf("RTMR[%d]: %x\n", i, rtmr[:])
		}
	}

	// Also show MrTd from the runtime TD Report
	fmt.Printf("\nMrTd (Trust Domain Measurement): %x\n", tdReport.MrTd[:])
	fmt.Printf("MrConfigId: %x\n", tdReport.MrConfigId[:])
	fmt.Printf("MrOwner: %x\n", tdReport.MrOwner[:])
	fmt.Printf("MrOwnerConfig: %x\n", tdReport.MrOwnerConfig[:])

	fmt.Println("\nRTMR Meanings:")
	fmt.Println("RTMR[0]: Static/dynamic configuration data")
	fmt.Println("RTMR[1]: OS kernel, boot parameters, initrd")
	fmt.Println("RTMR[2]: Additional boot components, ACPI tables")
	fmt.Println("RTMR[3]: Application-specific measurements")

	fmt.Println("\nNote: These are the RUNTIME RTMR values from the actual TD Report")
}

func validateQuoteStructure(quote *tdx.QuoteV4) {
	fmt.Println("\nQuote Structure Validation:")
	fmt.Println("===========================")
	
	// Check header
	header := quote.GetHeader()
	if header != nil {
		fmt.Printf("Quote Version: %d\n", header.GetVersion())
		fmt.Printf("Attestation Key Type: %d\n", header.GetAttestationKeyType())
		fmt.Printf("TEE Type: 0x%08x\n", header.GetTeeType())
		fmt.Printf("QE SVN: %x\n", header.GetQeSvn())
		fmt.Printf("PCE SVN: %x\n", header.GetPceSvn())
	} else {
		fmt.Println("❌ No header found")
		return
	}
	
	// Check signed data
	signedData := quote.GetSignedData()
	if signedData != nil {
		signature := signedData.GetSignature()
		publicKey := signedData.GetEcdsaAttestationKey()
		
		fmt.Printf("Signature present: %t (%d bytes)\n", len(signature) > 0, len(signature))
		fmt.Printf("Public key present: %t (%d bytes)\n", len(publicKey) > 0, len(publicKey))
		
		if len(signature) == 64 && len(publicKey) == 64 {
			fmt.Println("✅ ECDSA P-256 signature format detected")
			
			// Try to validate signature structure (offline check)
			validateECDSASignature(quote, signature, publicKey)
				
		} else {
			fmt.Printf("❌ Unexpected signature/key sizes: sig=%d, key=%d\n", len(signature), len(publicKey))
		}
		
		// Show signature and public key
		if len(signature) > 0 {
			fmt.Printf("Signature: %s\n", hex.EncodeToString(signature))
		}
		if len(publicKey) > 0 {
			fmt.Printf("Public Key: %s\n", hex.EncodeToString(publicKey))
		}
		
	} else {
		fmt.Println("❌ No signed data found")
	}
	
	fmt.Println()
}

func validateECDSASignature(quote *tdx.QuoteV4, signature, publicKey []byte) {
	fmt.Println("\nSignature Validation (Offline Check):")
	fmt.Println("=====================================")
	
	// Parse ECDSA signature (r, s values)
	if len(signature) != 64 {
		fmt.Printf("❌ Invalid signature length: %d (expected 64)\n", len(signature))
		return
	}
	
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	
	fmt.Printf("Signature R: %s\n", hex.EncodeToString(signature[:32]))
	fmt.Printf("Signature S: %s\n", hex.EncodeToString(signature[32:]))
	
	// Parse public key (x, y coordinates)
	if len(publicKey) != 64 {
		fmt.Printf("❌ Invalid public key length: %d (expected 64)\n", len(publicKey))
		return
	}
	
	x := new(big.Int).SetBytes(publicKey[:32])
	y := new(big.Int).SetBytes(publicKey[32:])
	
	fmt.Printf("Public Key X: %s\n", hex.EncodeToString(publicKey[:32]))
	fmt.Printf("Public Key Y: %s\n", hex.EncodeToString(publicKey[32:]))
	
	// Validate public key is on P-256 curve
	if !elliptic.P256().IsOnCurve(x, y) {
		fmt.Println("❌ Public key is not on P-256 curve")
		return
	}
	fmt.Println("✅ Public key is valid P-256 point")
	
	// Create ECDSA public key
	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	
	// Create the signed data (header + TD report)
	signedPayload := createSignedPayload(quote)
	if signedPayload == nil {
		fmt.Println("❌ Could not create signed payload")
		return
	}
	
	// Hash the signed data
	hash := sha256.Sum256(signedPayload)
	fmt.Printf("Signed data hash: %s\n", hex.EncodeToString(hash[:]))
	
	// Verify signature
	valid := ecdsa.Verify(ecdsaPubKey, hash[:], r, s)
	if valid {
		fmt.Println("✅ Signature verification PASSED - Quote structure is valid!")
	} else {
		fmt.Println("❌ Signature verification FAILED")
		fmt.Println("   This could mean:")
		fmt.Println("   - Incorrect signed data construction")
		fmt.Println("   - Quote has been tampered with")
		fmt.Println("   - Different signing algorithm used")
	}
}

func createSignedPayload(quote *tdx.QuoteV4) []byte {
	// The signed payload typically includes the header and TD report
	// This is a simplified version - exact format depends on TDX spec
	
	header := quote.GetHeader()
	tdQuoteBody := quote.GetTdQuoteBody()
	
	if header == nil || tdQuoteBody == nil {
		return nil
	}
	
	// Convert to ABI bytes for proper formatting
	headerBytes, err := abi.HeaderToAbiBytes(header)
	if err != nil {
		fmt.Printf("Warning: Could not convert header to ABI bytes: %v\n", err)
		return nil
	}
	
	tdQuoteBodyBytes, err := abi.TdQuoteBodyToAbiBytes(tdQuoteBody)
	if err != nil {
		fmt.Printf("Warning: Could not convert TD quote body to ABI bytes: %v\n", err)
		return nil
	}
	
	// Concatenate header + TD report (this is what gets signed)
	signedData := make([]byte, 0, len(headerBytes)+len(tdQuoteBodyBytes))
	signedData = append(signedData, headerBytes...)
	signedData = append(signedData, tdQuoteBodyBytes...)
	
	fmt.Printf("Signed payload length: %d bytes\n", len(signedData))
	
	return signedData
}