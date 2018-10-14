package main

import (
	"github.com/luopengift/log"
	"github.com/luopengift/ssh"
)

func main() {
	endpoint := ssh.NewEndpointWithValue("testing", "test", "127.0.0.1", "22", "luopengift", "xxx", "~/.ssh/id_rsa")
	//f, _ := os.OpenFile("a.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	f := log.NewFile("/tmp/ssh.%Y%M%D-%h%m")
	//defer f.Close()
	endpoint.SetWriters(f)
	if err := endpoint.StartTerminal(); err != nil {
		log.Error("%v", err)
	}
	log.Info("ok...")
}
