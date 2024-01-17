package main

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

/*
A note about the provided keys and signatures:
the provided pubkey and signature, as well as "HexTo___" functions may not work
with all the different implementations people could built.  Specifically, they
are tied to an endian-ness.  If, for example, you decided to encode your public
keys as (according to the diagram in the slides) up to down, then left to right:
<bit 0, row 0> <bit 0, row 1> <bit 1, row 0> <bit 1, row 1> ...

then it won't work with the public key provided here, because it was encoded as
<bit 0, row 0> <bit 1, row 0> <bit 2, row 0> ... <bit 255, row 0> <bit 0, row 1> ...
(left to right, then up to down)

so while in class I said that any decisions like this would work as long as they
were consistent... that's not actually the case!  Because your functions will
need to use the same ordering as the ones I wrote in order to create the signatures
here.  I used what I thought was the most straightforward / simplest encoding, but
endian-ness is something of a tabs-vs-spaces thing that people like to argue
about :).

So for clarity, and since it's not that obvious from the HexTo___ decoding
functions, here's the order used:

secret keys and public keys:
all 256 elements of row 0, most significant bit to least significant bit
(big endian) followed by all 256 elements of row 1.  Total of 512 blocks
of 32 bytes each, for 16384 bytes.
For an efficient check of a bit within a [32]byte array using this ordering,
you can use:
    arr[i/8]>>(7-(i%8)))&0x01
where arr[] is the byte array, and i is the bit number; i=0 is left-most, and
i=255 is right-most.  The above statement will return a 1 or a 0 depending on
what's at that bit location.

Messages: messages are encoded the same way the sha256 function outputs, so
nothing to choose there.

Signatures: Signatures are also read left to right, MSB to LSB, with 256 blocks
of 32 bytes each, for a total of 8192 bytes.  There is no indication of whether
the provided preimage is from the 0-row or the 1-row; the accompanying message
hash can be used instead, or both can be tried.  This again interprets the message
hash in big-endian format, where
    message[i/8]>>(7-(i%8)))&0x01
can be used to determine which preimage block to reveal, where message[] is the
message to be signed, and i is the sequence of bits in the message, and blocks
in the signature.

Hopefully people don't have trouble with different encoding schemes.  If you
really want to use your own method which you find easier to work with or more
intuitive, that's OK!  You will need to re-encode the key and signatures provided
in signatures.go to match your ordering so that they are valid signatures with
your system.  This is probably more work though and I recommend using the big
endian encoding described here.

*/

// Forge is the forgery function, to be filled in and completed.  This is a trickier
// part of the assignment which will require the computer to do a bit of work.
// It's possible for a single core or single thread to complete this in a reasonable
// amount of time, but may be worthwhile to write multithreaded code to take
// advantage of multi-core CPUs.  For programmers familiar with multithreaded code
// in golang, the time spent on parallelizing this code will be more than offset by
// the CPU time speedup.  For programmers with access to 2-core or below CPUs, or
// who are less familiar with multithreaded code, the time taken in programming may
// exceed the CPU time saved.  Still, it's all about learning.
// The Forge() function doesn't take any inputs; the inputs are all hard-coded into
// the function which is a little ugly but works OK in this assigment.
// The input public key and signatures are provided in the "signatures.go" file and
// the code to convert those into the appropriate data structures is filled in
// already.
// Your job is to have this function return two things: A string containing the
// substring "forge" as well as your name or email-address, and a valid signature
// on the hash of that ascii string message, from the pubkey provided in the
// signatures.go file.
// The Forge function is tested by TestForgery() in forge_test.go, so if you
// run "go test" and everything passes, you should be all set.go run

var usedIndices []int
var mySecKey SecretKey

func Forge() (string, Signature, error) {
	// decode pubkey, all 4 signatures into usable structures from hex strings
	pub, err := HexToPubkey(HexPubkey1)
	if err != nil {
		panic(err)
	}

	sig1, err := HexToSignature(HexSignature1)
	if err != nil {
		panic(err)
	}
	sig2, err := HexToSignature(HexSignature2)
	if err != nil {
		panic(err)
	}
	sig3, err := HexToSignature(HexSignature3)
	if err != nil {
		panic(err)
	}
	sig4, err := HexToSignature(HexSignature4)
	if err != nil {
		panic(err)
	}

	var sigslice []Signature
	sigslice = append(sigslice, sig1)
	sigslice = append(sigslice, sig2)
	sigslice = append(sigslice, sig3)
	sigslice = append(sigslice, sig4)

	var msgslice []Message

	msgslice = append(msgslice, GetMessageFromString("1"))
	msgslice = append(msgslice, GetMessageFromString("2"))
	msgslice = append(msgslice, GetMessageFromString("3"))
	msgslice = append(msgslice, GetMessageFromString("4"))

	fmt.Printf("ok 1: %v\n", Verify(msgslice[0], pub, sig1))
	fmt.Printf("ok 2: %v\n", Verify(msgslice[1], pub, sig2))
	fmt.Printf("ok 3: %v\n", Verify(msgslice[2], pub, sig3))
	fmt.Printf("ok 4: %v\n", Verify(msgslice[3], pub, sig4))

	msgString := "my forged message"
	m := GetMessageFromString(msgString)
	var sig Signature

	updateUsedIndices(sig1.Preimage, pub)
	updateUsedIndices(sig2.Preimage, pub)
	updateUsedIndices(sig3.Preimage, pub)
	updateUsedIndices(sig4.Preimage, pub)

	fmt.Printf("Number of elements is %d", len(usedIndices))

	missingIndexes := FindMissingIndexes(usedIndices, 512)

	//fmt.Printf("missing are %v\n", missingIndexes)
	fmt.Printf("Leng of missing is %d", len(missingIndexes))

	// your code here!
	// ==
	// Example: Initialize a wait group to wait for all goroutines to finish
	// Example: Initialize a wait group to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Use a mutex to protect access to the secret key slice
	var mu sync.Mutex

	// Start the number of goroutines equal to the number of missing indexes
	// Start the number of goroutines equal to the number of missing indexes
	for _, missingIndex := range missingIndexes {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			for {
				// Generate a random block
				randomBlock := generateRandomBlock()

				// Hash the block
				hashedBlock := sha256.Sum256(randomBlock[:])

				mu.Lock()

				index1 := index

				// Check if the index is greater than 255
				if index1 > 255 {
					// Adjusted index is greater than 255, compare with OneHash
					if hashedBlock == pub.OneHash[index1-256] {

						// Check if the secret key at the given index is already filled

						if mySecKey.OnePre[index1-256] == [32]byte{} {
							mySecKey.OnePre[index1-256] = randomBlock
							fmt.Printf("Generated secretkey for block number %d", index1)
						}

						// Check if the whole secret key structure is completely filled

						isFilled := true
						for _, block := range mySecKey.ZeroPre {
							if block == [32]byte{} {
								isFilled = false
								break
							}
						}
						for _, block := range mySecKey.OnePre {
							if block == [32]byte{} {
								isFilled = false
								break
							}
						}
						//mu.Unlock()

						// If the structure is completely filled, exit the goroutine
						if isFilled {
							mu.Unlock()
							return
						}
					}
				} else {
					// Index is less than or equal to 255, compare with ZeroHash
					if hashedBlock == pub.ZeroHash[index1] {

						// Check if the secret key at the given index is already filled
						//mu.Lock()
						if mySecKey.ZeroPre[index1] == [32]byte{} {
							mySecKey.ZeroPre[index1] = randomBlock
							fmt.Printf("Generated secretkey for block number %d", index1)
						}
						//mu.Unlock()

						// Check if the whole secret key structure is completely filled
						//mu.Lock()
						isFilled := true
						for _, block := range mySecKey.ZeroPre {
							if block == [32]byte{} {
								isFilled = false
								break
							}
						}
						for _, block := range mySecKey.OnePre {
							if block == [32]byte{} {
								isFilled = false
								break
							}
						}
						//mu.Unlock()

						// If the structure is completely filled, exit the goroutine
						if isFilled {
							mu.Unlock()
							return
						}
					}
				}

				// If there's no match, try again with a new random block
				mu.Unlock()
			}
		}(missingIndex)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// ==
	areEqual := true

	for i, block := range mySecKey.ZeroPre {
		if sha256.Sum256(block[:]) != pub.ZeroHash[i] {
			areEqual = false
			break
		}
	}

	// Compare the OnePre blocks
	for i, block := range mySecKey.OnePre {
		if sha256.Sum256(block[:]) != pub.OneHash[i] {
			areEqual = false
			break
		}
	}
	// Print the result
	fmt.Println("Structures are equal:", areEqual)

	finalsig := Sign(m, mySecKey)

	return msgString, finalsig, nil

}

// Simulated function to update the used indices
func updateUsedIndices(preimage [256]Block, publicKey PublicKey) {
	for _, block := range preimage {
		// Simulated hash of the block
		hashedBlock := sha256.Sum256(block[:])

		// Simulated comparison with the public key
		for j, hashedZero := range publicKey.ZeroHash {
			if hashedZero == hashedBlock {
				// Check if the index is already present in usedIndices
				if !containsIndex(j, usedIndices) {
					usedIndices = append(usedIndices, j)
					mySecKey.ZeroPre[j] = block
				}
			}
		}

		for j, hashedOne := range publicKey.OneHash {
			if hashedOne == hashedBlock {
				// Check if the index is already present in usedIndices
				if !containsIndex(j+255, usedIndices) {
					usedIndices = append(usedIndices, j+255)
					mySecKey.OnePre[j] = block
				}
			}
		}
	}
}

// Function to check if an index is present in a slice
func containsIndex(index int, indices []int) bool {
	for _, i := range indices {
		if i == index {
			return true
		}
	}
	return false
}

func FindMissingIndexes(array []int, totalIndexes int) []int {
	// Create a map to store present indexes
	presentIndexes := make(map[int]bool)

	// Mark present indexes in the map
	for _, index := range array {
		presentIndexes[index] = true
	}

	// Find missing indexes
	var missingIndexes []int
	for i := 0; i < totalIndexes; i++ {
		if !presentIndexes[i] {
			missingIndexes = append(missingIndexes, i)
		}
	}

	return missingIndexes
}

// hint:
// arr[i/8]>>(7-(i%8)))&0x01
