package main

import (
	"fmt"
	"log"
	"os/exec"
  "io/ioutil"
  "os"
	"regexp"
	"math/rand"
)

func main() {


	if (len(os.Args) != 3) {
		fmt.Println(" Invalid command line option, follow the specification")
	} else {

  ciphertextFilename := os.Args[2]
	aesBlocksize := 16
	fileContent, err_data_file := ioutil.ReadFile(ciphertextFilename)
	/* Error handling if file wasn't opened successfully */
	if (err_data_file != nil) {
		fmt.Println("Invalid file name, doesn't exist")
	}
	lenFileContent := len(fileContent)
	numberOfBlocks := lenFileContent/aesBlocksize
	fmt.Println("Number of blocks is ", numberOfBlocks)

	// Create a copy of the file
	fileContentCopyComplete := make([]byte, lenFileContent)
	fileContentCopyCompleteLength := copy(fileContentCopyComplete, fileContent)

	if fileContentCopyCompleteLength == 0 {
		fmt.Println("Copy problem")
	}
	holder := make([]byte, 1)
	for i := 0; i < 11; i++ {

		fileContentVariable := fileContent[0:(lenFileContent - (16 * i))]
		err := ioutil.WriteFile("ciphertext.txt", fileContentVariable, 0644)
		if (err != nil) {
			fmt.Println("Invalid file name, doesn't exist")
			}

			plaintext := make([]byte, 16)
			decryptedText  := testForVariyingCiphertext(ciphertextFilename)
			plaintextLength := copy(plaintext, decryptedText)
			if plaintextLength == 0 {
				fmt.Println("Copy problem")
			}
			//fmt.Println("Returned plaintext is", plaintext)

			for j := 0; j < 16; j++ {
				holder = append(holder, plaintext[j])
			}
		}

		holder = holder[1 : len(holder)]
		//fmt.Println("Holder is ", holder)

		finalPlaintextBlock := make([]byte, 1)
		multipleFinalPlaintextBlock := (len(holder))/16
	//	fmt.Println("multipleFinalPlaintextBlock is ", multipleFinalPlaintextBlock)

		for t:= multipleFinalPlaintextBlock; t > 0 ; t-- {

			for z := 0; z < 16; z++ {

			finalPlaintextBlock = append(finalPlaintextBlock, holder[(((t - 1)*16) + z)])

			}
		}

		finalPlaintextBlock = finalPlaintextBlock[1:len(finalPlaintextBlock)]

		fmt.Println("Final plaintext is ", finalPlaintextBlock)

		err := ioutil.WriteFile("ciphertext.txt", fileContentCopyComplete, 0644)
		if (err != nil) {
			fmt.Println("Invalid file name, doesn't exist")
			}
	}

}


func testForPad() ([]byte) {

	cmd := exec.Command("./encrypt-auth", "decrypt" ,"-k", "364c7394759b039b9a93849abc938e9e3248932832498acb34cbaef324385bc3","-i","ciphertext.txt","-o","recoveredplaintext.txt")
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
	return stdoutStderr

}


func testForVariyingCiphertext(ciphertextFilename string) ([]byte) {

	aesBlocksize := 16
	plaintextBookKeeping := make([]byte,aesBlocksize)
	intermediateStateByteArray := make([]byte,aesBlocksize)
	fileContent, err_data_file := ioutil.ReadFile(ciphertextFilename)

	residue := 0
	intermediateStateByte := byte(0)
  /* Error handling if file wasn't opened successfully */
  if (err_data_file != nil) {
    fmt.Println("Invalid file name, doesn't exist")
  }
	lenFileContent := len(fileContent)
	fileContentCopy := make([]byte, lenFileContent)
	fileContentCopyBytes := copy(fileContentCopy,fileContent)
	if fileContentCopyBytes == 0 {
		fmt.Println(" Copying problem")
	}
	// TODO Hardcoding now, to be removed later
//	fmt.Println(" File content is ", fileContent)
	secondLastBlockBytes := make([]byte, 16)

	for i := 0; i < 16; i++ {

		secondLastBlockBytes[i] = fileContent[lenFileContent - 32 + i]
	}
	//fmt.Println("Second last block is ", secondLastBlockBytes)

	// Outer loop for looping through individual bytes of the second last block
	for i := 1; i <= aesBlocksize; i++ {

			residue = aesBlocksize - i;
		//	fmt.Println("Residue for i = ", i, " is ", residue)

			for j := 1; j <= residue; j++ {

				index := lenFileContent - 16 - (i + j)
				fileContent[index] = byte(rand.Int31n(255))
				//fmt.Println("Random byte for index  = ", index, " is ", fileContent[index])

					}

				for f := 1; f < i; f++ {

					fileContent[lenFileContent - 16 -f] = intermediateStateByteArray[16 - f] ^ byte(i)
				}

			err := ioutil.WriteFile("ciphertext.txt", fileContent, 0644)
			if (err != nil) {
		    fmt.Println("Invalid file name, doesn't exist")
		  }

				for k := 0; k < 255; k++ {

					fileContent[lenFileContent - 16 - i] = byte(k)
					re := regexp.MustCompile(`\r?\n`)

					err := ioutil.WriteFile("ciphertext.txt", fileContent, 0644)
					if (err != nil) {
				    fmt.Println("Invalid file name, doesn't exist")
				  }

					testForPadOutput := testForPad()
					testForPadOutputString := string(testForPadOutput)
					testForPadOutputString = re.ReplaceAllString(testForPadOutputString, "")

					if testForPadOutputString != "INVALID PADDING" {
						intermediateStateByte = byte(k)
						//fmt.Println("intermediateStateByte for i = ", i, " is " ,intermediateStateByte)
						//fileContent[(lenFileContent - 32):(lenFileContent -16)] = secondLastBlockBytes

						for c := 0; c < 16; c++ {

							fileContent[lenFileContent - 32 + c] = secondLastBlockBytes[c]
							//fmt.Println(" File content being written is ",fileContent[lenFileContent - 32 + c], " and in second last block we have", secondLastBlockBytes[c] )
						}

						err = ioutil.WriteFile("ciphertext.txt", fileContent, 0644)
						break
						}

				}

				fileContent, err_data_file = ioutil.ReadFile(ciphertextFilename)
				if (err_data_file != nil) {
					fmt.Println("Invalid file name, doesn't exist")
				}
				intermediateStateByteArray[16 - i] = intermediateStateByte ^ byte(i)
				plaintextBookKeeping[ 16 - i] = (fileContent[lenFileContent - 16 - i]) ^ (intermediateStateByteArray[ 16 - i])
			//	fmt.Println(" PLaintext text writtent at ", 16 - i, " position is ", plaintextBookKeeping[ 16 - i])

				// Writing back original contents to file before next operation
				err = ioutil.WriteFile("ciphertext.txt", fileContentCopy, 0644)
	}
		//fmt.Println("Decrypted plaintext in last block is", (plaintextBookKeeping))
		return plaintextBookKeeping


}
