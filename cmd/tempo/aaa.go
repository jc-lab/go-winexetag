package main

import (
	exetag "github.com/ianatha/go-winexetag"
	"log"
	"os"
)

func main() {
	f, err := os.Open("/data/workspace/zerox/zerox-agent/go/app-buildin-data/test/signed_sample.patched.exe")
	if err != nil {
		log.Fatalln(err)
	}
	//f2, err := os.OpenFile("/data/workspace/zerox/zerox-agent/go/app-buildin-data/test/signed_sample.patched.exe", os.O_CREATE|os.O_RDWR, 0644)
	//if err != nil {
	//	log.Fatalln(err)
	//}

	binary, err := exetag.NewPE32Binary(f)
	if err != nil {
		log.Fatalln(err)
	}

	tag, err := binary.GetTag()
	if err != nil {
		log.Println("TAG_NO: ", err)
	} else {
		log.Println("TAG_OK: ", string(tag))
	}
	//
	//err = binary.SetTag(f2, []byte("hello world!!!"))
	//if err != nil {
	//	log.Println("SET_NO: ", err)
	//} else {
	//	log.Println("SET_OK: ")
	//}
	//f.Close()
	//f2.Close()
}
