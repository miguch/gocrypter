package main

import (
	"encoding/binary"
	"fmt"
	"github.com/miguch/gocrypter/crypter"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"runtime/debug"
	"sync"
)

var crypt *crypter.Crypter

func encryptFile(filename string, passphrase string) (cipher []byte, err error) {
	nameLen := [4]byte{}
	binary.LittleEndian.PutUint32(nameLen[:], uint32(len(filename)))
	nameBlock := make([]byte, 0, 4+len(filename))
	nameBlock = append(nameBlock, nameLen[:]...)
	nameBlock = append(nameBlock, []byte(filename)...)

	plainData, err := ioutil.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}

	return crypt.Encrypt(append(nameBlock, plainData...), crypt.GetPublicKey())
}

func decryptFile(filename string, passphrase string) (originName string, plain []byte, err error) {
	cipher, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", []byte{}, err
	}
	if len(cipher) <= 4 {
		return "", []byte{}, errors.New(fmt.Sprintf("Skip %v", filename))
	}

	plainData, err := crypt.Decrypt(cipher)
	if err != nil {
		return "", []byte{}, err
	}

	nameLen := binary.LittleEndian.Uint32(plainData[:4])
	originName = string(plainData[4 : 4+nameLen])
	plain = plainData[4+nameLen:]
	return
}

const encryptPath = "crypted"
const decryptPath = "output"

var waitGroup = sync.WaitGroup{}

func main() {
	files, err := ioutil.ReadDir("./")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load directory: %v\n", err)
		os.Exit(1)
	}

	decryptModePtr := pflag.BoolP("decrypt", "d", false, "Specify to decrypt current directory.")
	maxRunningPtr := pflag.IntP("Parallel", "j", runtime.NumCPU(), "The number of parallel jobs,")
	singleFile := pflag.StringP("File", "f", "", "A single file to be operated.")
	pflag.Parse()
	decryptMode := *decryptModePtr
	if len(pflag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "A passphrase must be specified!\n")
		os.Exit(1)
	}
	passPhrase := pflag.Arg(0)

	var outputPath string

	if decryptMode {
		outputPath = decryptPath
		fmt.Println("Decrypting...")
	} else {
		outputPath = encryptPath
		fmt.Println("Encrypting...")
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		err = os.Mkdir(outputPath, os.ModePerm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
			os.Exit(1)
		}
	}

	crypt, err = crypter.NewCrypter(passPhrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create crypter: %v\n", err)
		os.Exit(1)
	}

	if len(*singleFile) != 0 {
		fip, err := os.Lstat(*singleFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot Open file %v: %v\n", *singleFile, err)
		}
		files = []os.FileInfo {
			fip,
		}
	}

	maxRunning := *maxRunningPtr
	runtime.GOMAXPROCS(maxRunning)
	fmt.Printf("Using up to %v routines\n", maxRunning)

	ch := make(chan int)
	runningCount := 0

	for ind, f := range files {
		waitGroup.Add(1)
		go func(f os.FileInfo, ind int, decryptMode bool, wg *sync.WaitGroup) {
			defer func() {
				ch <- 1
			}()
			defer wg.Done()
			if decryptMode {

				name, plain, err := decryptFile(f.Name(), passPhrase)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Skip %v: %v\n", f.Name(), err)
					return
				}
				err = ioutil.WriteFile(path.Join(outputPath, name), plain, 0644)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
					return
				}

				fmt.Printf("Decrypted %v.\n", name)
			} else {

				ci, err := encryptFile(f.Name(), passPhrase)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Skip %v: %v\n", f.Name(), err)
					return
				}

				err = ioutil.WriteFile(path.Join(outputPath, fmt.Sprintf("%v.ci", ind)), ci, 0644)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
					return
				}
				fmt.Printf("Encrypted %v.\n", f.Name())
			}

		}(f, ind, decryptMode, &waitGroup)
		runningCount += 1

		if runningCount >= maxRunning {
			runningCount -= <-ch
			runtime.GC()
			debug.FreeOSMemory()
		}
	}
	waitGroup.Wait()

	fmt.Println("Done.")
}
