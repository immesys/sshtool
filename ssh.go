package sshtool

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"
)

type SSHRunner struct {
	target string
	cl     *ssh.Client

	keyfile  string
	username string
}

func NewSSHRunner(keyfile, username, host string) (*SSHRunner, error) {
	rv := &SSHRunner{target: host, keyfile: keyfile, username: username}
	content, err := rv.RunBash(context.Background(), "echo shell ok")
	if err != nil {
		return nil, fmt.Errorf("check failed, got %v\n", err)
	}
	if string(content) != "shell ok\n" {
		return nil, fmt.Errorf("check failed, got %q expected %q\n", string(content), "shell ok\n")
	}
	return rv, nil
}

func publicKeyFile(file string) (ssh.AuthMethod, error) {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(key), nil
}

func (sr *SSHRunner) config() *ssh.ClientConfig {
	//Get keyfiles
	kf, err := publicKeyFile(sr.keyfile)
	if err != nil {
		panic(fmt.Sprintf("cannot load key file %v\n", err))
	}
	return &ssh.ClientConfig{
		User: sr.username,
		Auth: []ssh.AuthMethod{kf},
	}
}

//PutFile will copy a local file to a remote file name and set its mode.
func (sr *SSHRunner) PutFile(ctx context.Context, lfilename string, rfilename string, mode os.FileMode) error {
	file, err := os.Open(lfilename)
	if err != nil {
		return err
	}
	sinfo, err := file.Stat()
	if err != nil {
		return err
	}
	return sr.PutStream(ctx, file, sinfo.Size(), rfilename, mode)
}

//PutBlob will write the given array to a file on the remote machine with the given mode
func (sr *SSHRunner) PutBlob(ctx context.Context, arr []byte, rfilename string, mode os.FileMode) error {
	rdr := bytes.NewReader(arr)
	rv := sr.PutStream(ctx, rdr, int64(len(arr)), rfilename, mode)
	return rv
}

//PutStream will streaming write from a reader to a remote file. The size of the stream must be known in advance
//and given correctly
func (sr *SSHRunner) PutStream(ctx context.Context, stream io.Reader, size int64, rfilename string, mode os.FileMode) error {
	sess, err := sr.session(ctx)
	if err != nil {
		return err
	}
	w, _ := sess.StdinPipe()
	go func() {
		wr := fmt.Sprintf("C%#o %d %s\n", mode, size, "blob")
		w.Write([]byte(wr))
		io.Copy(w, stream)
		fmt.Fprint(w, "\x00")
		w.Close()
	}()
	cmd := fmt.Sprintf("scp -t %s", rfilename)
	err = sess.Run(cmd)
	if err != nil {
		return err
	}
	return nil
}

//Cat will return the contents of a remote file
func (sr *SSHRunner) Cat(ctx context.Context, rfilename string) ([]byte, error) {
	sess, err := sr.session(ctx)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	rv, err := sess.CombinedOutput("/bin/cat " + rfilename)
	if err == nil {
		return rv, nil
	}
	return nil, err
}

//RunBash will run the command as if it were interpreted in a bash shell
//and return the result.
func (sr *SSHRunner) RunBash(ctx context.Context, command string) ([]byte, error) {
	sess, err := sr.session(ctx)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	w, _ := sess.StdinPipe()
	go func() {
		w.Write([]byte(command))
		w.Close()
	}()
	return sess.CombinedOutput("/bin/bash -s")
}

//RunRootBash will run the command in a root shell on the remote side and return
//the result
func (sr *SSHRunner) RunRootBash(ctx context.Context, command string) ([]byte, error) {
	sess, err := sr.session(ctx)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	w, _ := sess.StdinPipe()
	go func() {
		w.Write([]byte(command))
		w.Close()
	}()
	//TODO change this for things like containers what don't have sudo or are already root
	return sess.CombinedOutput("sudo /bin/bash -s")
}

func (sr *SSHRunner) session(ctx context.Context) (*ssh.Session, error) {
	if sr.cl == nil {
		cl, err := sr.login(ctx)
		if err != nil {
			return nil, err
		}
		sr.cl = cl
	}
	sess, err := sr.cl.NewSession()
	return sess, err
}

func (sr *SSHRunner) login(ctx context.Context) (*ssh.Client, error) {
	connection, err := ssh.Dial("tcp", sr.target, sr.config())
	if err == nil {
		return connection, nil
	}
	return nil, err
}
