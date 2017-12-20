package main

import (
	"crypto/aes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
)

var key = "nfy899iQXpBuEQATHwWVmpXTqZf6vfCL"
var crypted = "wLjKN3LwcHFGLycZOCO5sE0PYURUZ/LXBuR0IJFe7KQgx9+Ndl7RIR9ag1H+vDNa8ymegl23iLKsyF13hAM9qXr1BfOTpEYA7Xp0cC/WA39hgUVB5tUuksXAaVXUKx7oU0cq3mmFD39M3MtorXu0510/PUXwuOM8Jg5QLpa8NjeMAgyxX+MRMtj+CnEun4ei6FpdfTiZLPptkJrEEsP4TOAVpruYnYR4Eu+p/MTvkZJh5VEhSpfq/xiVZee8Zl0Ez+jqgQt+q7fpnpwvSzUgahoLUZqvauBxFnmcyLorqyCvvD6ZbWF5khI/HOnmiBx2ijfEyL0vIt0YTOW21qWR85Jq4krD/q1LGlv9QJddwH43Xl017qnoq8oYoO+rkIPM6GvEZfS+kMWztzOtmh/ZOA30+wO0c06413Aw2K14IpcEmLXtYGn/hxw7gPxGe22efq6/PbT88I0pYrPSnkjaeRI/4hAk6iHvjBs8kjHXcCM84x08W5ZJ7PePqkS1Ggn5ZWekvVQyeI/3khTXauJU+mwCF0K6th0cDVKzWcRQJgrRiHLFC3TPV/AUxPIwiIXETkN6KRKQuWPkL07quMy5cAB1Y8h9RtXsVub6nTyqSfdoUBLHsOE1BNq863e8wEbS57nUaNS/3WppaZz7qpRoxs/o6oELfqu36Z6cL0s1IGomnvhLrxzaQ0LQrbQtReLP4nhiuiFqJoKJOWCFm2uuME2l1Qson3vmlnQg6ObvGTrRLd690qyfnm+GvIDEQi+wS6jpF4vr5lwsT+PXYa1cnNaZML0akxSGFGksTXF30QvIONv/fgW7D7gPtHLMG1xQxcovacpQ4Q86oHqnt6HP8aIB4OyfdKZZEvhXGBVspG7m6iyR6CiuVvpiQlT6E3Zq0S3evdKsn55vhryAxEIvsFDAGGbyZ1aSzYAbx1ao51jw8fopL/t+2+ifWFQjOrUJWVqkRWpUTbG+DX8PfpKgVEaRbviOifo5D5ggbuek5azUCThV1UP0VdsvhMrj+yrPgnZZo2Ae96137587kQ6yBalYuAnVEzQvZRfFdtw0ong="

func init() {

}

func main() {
	// 1. decode Base64
	deBase64, err := base64.StdEncoding.DecodeString(crypted)
	// 2. md5 original trading key
	hasher := md5.New()
	hasher.Write([]byte(key))
	result := hex.EncodeToString(hasher.Sum(nil))

	//3. aes ecb decrypt
	block, err := aes.NewCipher([]byte(result))
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBDecrypter(block)
	content := []byte(deBase64)
	mode.CryptBlocks(content, content)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	content, err = padder.Unpad(content)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", content)
}
