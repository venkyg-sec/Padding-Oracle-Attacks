package main

import (
	"fmt"
	"log"
	"os/exec"
  "io/ioutil"
  "os"
	"regexp"
)

func main() {


	if (len(os.Args) != 2) {
		fmt.Println(" Invalid command line option, follow the specification")
	} else {

  ciphertextFilename := os.Args[1]
  fileContent, err_data_file := ioutil.ReadFile(ciphertextFilename)
  /* Error handling if file wasn't opened successfully */
  if (err_data_file != nil) {
    fmt.Println("Invalid file name, doesn't exist")
  }
	lenFileContent := len(fileContent)


	//fileContent[lenFileContent - 1] = byte(56)

	// Construct a regular expression to strip new line characters
	re := regexp.MustCompile(`\r?\n`)


paddingLength := 0
	for i := 1; i <= 16; i++ {

			ithByte := fileContent[lenFileContent - 16 - i]
			//fmt.Println("Last byte before overwriting is ",fileContent[lenFileContent - i] )
			fileContent[lenFileContent - 16 - i] = byte(4)
			//fmt.Println("Last byte is ",fileContent[lenFileContent - 16 - i] )
			err := ioutil.WriteFile("ciphertext.txt", fileContent, 0644)
			// Condition to check if writing to the file has failed
			if err != nil {
				fmt.Println("Error opening file")
			}

			testForPadOutput := testForPad()
			testForPadOutputString := string(testForPadOutput)
			testForPadOutputString = re.ReplaceAllString(testForPadOutputString, "")
			//fmt.Println(testForPadOutputString, " and len is ", len(testForPadOutputString))
			fileContent[lenFileContent - 16 - i] = ithByte
			//fmt.Println("Last byte after check for padding is  ",fileContent[lenFileContent -16 - i] )
			err = ioutil.WriteFile("ciphertext.txt", fileContent, 0644)
			if testForPadOutputString != "INVALID PADDING" {
					paddingLength = i - 1
					break
					}
				}
		fmt.Println("Padding Length is ", paddingLength)
		}

		testForVariyingCiphertext("ciphertext.txt")

}


func testForPad() ([]byte) {

	cmd := exec.Command("./encrypt-auth", "decrypt" ,"-k", "364c7394759b039b9a93849abc938e9e3248932832498acb34cbaef324385bc3","-i","ciphertext.txt","-o","recoveredplaintext.txt")
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	return stdoutStderr


}


func testForVariyingCiphertext(ciphertextFilename string) {

	// TODO - Just testing if thee logic actually works, clean up later
	// logic - Mall the previous block to capture the current block
	fileContent, err_data_file := ioutil.ReadFile(ciphertextFilename)
	if (err_data_file != nil) {
    fmt.Println("Invalid file name, doesn't exist")
  }
	lenFileContent := len(fileContent)
	lastBlock := fileContent[(lenFileContent) -16 : lenFileContent]
	secondLastBlock := fileContent[(lenFileContent -32): (lenFileContent -16)]

	// TODO Remove print statements
	fmt.Println("Last block is ",lastBlock)
	fmt.Println("Second Last block is",secondLastBlock)
	fmt.Println("File content is",fileContent)

	actualLastByteSecondLastBlock := fileContent[lenFileContent - 16 - 1]
	actualSecondLastByteSecondLastBlock := fileContent[lenFileContent - 16 - 2]
	actualThirdLastByteSecondLastBlock := fileContent[lenFileContent - 16 - 3]

	fmt.Println("Actual byte in second last block is",actualLastByteSecondLastBlock)

	intermediateStateByte := 0
	for i := 0; i < 255; i++ {

		fileContent[lenFileContent - 16 - 1] = byte(i)
		fileContent[lenFileContent - 16 - 2] = byte(24)
		fileContent[lenFileContent - 16 - 3] = byte(45)

		re := regexp.MustCompile(`\r?\n`)

		err := ioutil.WriteFile("ciphertext.txt", fileContent, 0644)
		if (err != nil) {
	    fmt.Println("Invalid file name, doesn't exist")
	  }
		testForPadOutput := testForPad()
		testForPadOutputString := string(testForPadOutput)
		testForPadOutputString = re.ReplaceAllString(testForPadOutputString, "")

		if testForPadOutputString != "INVALID PADDING" {
			intermediateStateByte = i
			fileContent[lenFileContent - 16 - 1] = actualLastByteSecondLastBlock
			fileContent[lenFileContent - 16 - 2] = actualSecondLastByteSecondLastBlock
			fileContent[lenFileContent - 16 - 3] = actualThirdLastByteSecondLastBlock
			
			err = ioutil.WriteFile("ciphertext.txt", fileContent, 0644)
			break
			}

		}
		fmt.Println("I got Valid padding for i = ", intermediateStateByte)
		fileContent, err_data_file = ioutil.ReadFile(ciphertextFilename)
		intermediateStateByte1 := byte(intermediateStateByte) ^ byte(1)
		requiredPLaintext := (fileContent[lenFileContent - 16 - 1]) ^ intermediateStateByte1
		fmt.Println(fileContent)
		fmt.Println(byte(intermediateStateByte1))
		fmt.Println(fileContent[lenFileContent - 16 - 1])
		fmt.Println(byte(requiredPLaintext))


}

/* Function to XOR 2 Byte Arrays */
func XorBytes(ivPlaintext, iv, plaintext []byte) int {

	ivLength := len(iv)
  if len(plaintext) < ivLength {
    ivLength = len(plaintext)

	}

	for i := 0; i < ivLength; i++ {
    ivPlaintext[i] = iv[i] ^ plaintext[i]
  }
  return ivLength
}
