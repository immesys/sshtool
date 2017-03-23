package main

import (
	"fmt"

	"github.com/immesys/sshtool"
)

func main() {
	sh, err := sshtool.NewSSHRunner("/home/immesys/.ssh/id_rsa", "immesys", "10.4.10.50:22")
	if err != nil {
		panic(err)
	}
	_ = sh
	fmt.Printf("ok!\n")
}
