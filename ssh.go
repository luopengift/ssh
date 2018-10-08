package ssh

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/luopengift/types"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// Endpoint Endpoint
type Endpoint struct {
	Name      string            `yaml:"name"`
	Host      string            `yaml:"host"`
	IP        string            `yaml:"ip"`
	Port      string            `yaml:"port"`
	User      string            `yaml:"user"`
	Password  string            `yaml:"password"`
	Passwords []string          `yaml:"passwords"` //密码列表
	Key       string            `yaml:"key"`
	QAs       map[string]string `yaml:"qas"` //questions-answers
	Timeout   int               `yaml:"timeout"`
	writers   []io.Writer       // this is used for screen stream copy or backup
}

// NewEndpoint NewEndpoint
func NewEndpoint() *Endpoint {
	return new(Endpoint)
}

// NewEndpointWithValue NewEndpointWithValue
func NewEndpointWithValue(name, host, ip, port, user, password, key string, writers ...io.Writer) *Endpoint {
	return &Endpoint{
		Name:     name,
		Host:     host,
		IP:       ip,
		Port:     port,
		User:     user,
		Password: password,
		Key:      key,
		Timeout:  5,
		writers:  writers,
	}
}

// Init Init
func (ep *Endpoint) Init(filename string) error {
	return types.ParseConfigFile(filename, ep)
}

// SetTimeout SetTimeout
func (ep *Endpoint) SetTimeout(timeout int) {
	ep.Timeout = timeout
}

// SetWriters this method is useful in StartTerminal
func (ep *Endpoint) SetWriters(writers ...io.Writer) {
	ep.writers = writers
}

// 解析登录方式
func (ep *Endpoint) authMethods() ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod
	var err error

	passwords := []string{ep.Password}
	passwords = append(passwords, ep.Passwords...)

	if length := len(passwords); length != 0 {
		n := 0
		authMethod := ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
			password := passwords[n]
			n++
			return password, nil
		}), length)
		authMethods = append(authMethods, authMethod)
	}

	if ep.Key != "" {
		var keyBytes []byte
		keyBytes, err = base64.StdEncoding.DecodeString(strings.TrimSpace(ep.Key)) // private key content, must base64 code
		if err != nil {
			filepath := strings.Replace(ep.Key, "~", os.Getenv("HOME"), -1)
			keyBytes, err = ioutil.ReadFile(filepath) //private key file
		}
		if err != nil {
			return authMethods, err
		}
		// Create the Signer for this private key.
		var signer ssh.Signer
		if ep.Password == "" {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(ep.Password))
		}
		if err != nil {
			return authMethods, err
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if ep.QAs != nil {
		answers := keyboardInteractive(ep.QAs)
		authMethods = append(authMethods, ssh.KeyboardInteractive(answers.Challenge))
	}
	return authMethods, nil
}

type keyboardInteractive map[string]string

func (cr keyboardInteractive) Challenge(user, instruction string, questions []string, echos []bool) ([]string, error) {
	var answers []string
	for _, question := range questions {
		answer, ok := cr[question]
		if !ok {
			return nil, fmt.Errorf("question[%s] not answer", question)
		}
		answers = append(answers, answer)
	}
	return answers, nil
}

// Address Address
func (ep *Endpoint) Address() string {
	if ep.IP != "" {
		return fmt.Sprintf("%s:%s", ep.IP, ep.Port)
	}
	return fmt.Sprintf("%s:%s", ep.Host, ep.Port)
}

// InitSSHClient InitSSHClient
func (ep *Endpoint) InitSSHClient() (*ssh.Client, error) {
	auths, err := ep.authMethods()
	if err != nil {
		return nil, fmt.Errorf("鉴权出错: %v", err)
	}

	config := &ssh.ClientConfig{
		User:            ep.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(ep.Timeout) * time.Second,
	}
	return ssh.Dial("tcp", ep.Address(), config)
}

// Upload Upload
func (ep *Endpoint) Upload(src, dest string) error {
	client, err := ep.InitSSHClient()
	if err != nil {
		return fmt.Errorf("建立ssh连接出错: %v", err)
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("建立sftp出错: %v", err)
	}
	defer sftpClient.Close()

	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("读取本地文件[%s]出错: %v", src, err)
	}
	defer srcFile.Close()

	destFile, err := sftpClient.Create(dest)
	if err != nil {
		return fmt.Errorf("创建远程文件[%s]出错: %v", dest, err)
	}
	defer destFile.Close()

	size := 0
	buf := make([]byte, 1024*1024)
	for {
		n, err := srcFile.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("上传文件read出错1: %v", err)
		}
		if n == 0 {
			break
		}
		if _, err := destFile.Write(buf[:n]); err != nil {
			return fmt.Errorf("上传文件write出错2: %v", err)
		}
		size += n
	}
	return nil
}

// Download Download
func (ep *Endpoint) Download(src, dest string) error {
	client, err := ep.InitSSHClient()
	if err != nil {
		return fmt.Errorf("建立ssh连接出错: %v", err)
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("建立sftp出错: %v", err)
	}
	defer sftpClient.Close()

	srcFile, err := sftpClient.Open(src)
	if err != nil {
		return fmt.Errorf("读取远程文件[%s]出错: %v", src, err)
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("创建本地文件[%s]出错: %v", dest, err)
	}
	defer destFile.Close()

	size := 0
	buf := make([]byte, 1024*1024)
	for {
		n, err := srcFile.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("下载文件read出错1: %v", err)
		}
		if n == 0 {
			break
		}
		if _, err := destFile.Write(buf[:n]); err != nil {
			return fmt.Errorf("下载文件write出错2: %v", err)
		}
		size += n
	}
	return nil
}

// CmdOutBytes CmdOutBytes
func (ep *Endpoint) CmdOutBytes(cmd string) ([]byte, error) {
	client, err := ep.InitSSHClient()
	if err != nil {
		return nil, fmt.Errorf("建立SSH连接出错: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("创建Session出错: %v", err)
	}
	defer sess.Close()

	return sess.CombinedOutput(cmd)
}

// StartTerminal StartTerminal
func (ep *Endpoint) StartTerminal() error {
	client, err := ep.InitSSHClient()
	if err != nil {
		return fmt.Errorf("建立SSH连接出错: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("创建Session出错: %v", err)
	}
	defer sess.Close()

	sess.Setenv("LANG", "zh_CN.UTF-8")
	sess.Stdin = os.Stdin

	if ep.writers == nil {
		sess.Stdout = os.Stdout
		sess.Stderr = os.Stderr
	} else {
		stdout, _ := sess.StdoutPipe()
		stderr, _ := sess.StderrPipe()

		outs := []io.Writer{os.Stdout}
		errs := []io.Writer{os.Stderr}

		outs = append(outs, ep.writers...)
		errs = append(errs, ep.writers...)

		go copyBuffer(outs, stdout, nil)
		go copyBuffer(errs, stderr, nil)
	}
	fd := int(os.Stdin.Fd())
	oldState, err := terminal.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("创建文件描述符出错: %v", err)
	}
	defer terminal.Restore(fd, oldState)

	width, height := 0, 0
	go func() error {
		t := time.NewTimer(time.Millisecond * 0)
		for {
			select {
			case <-t.C:
				width, height, err = terminal.GetSize(fd)
				if err != nil {
					return fmt.Errorf("获取窗口宽高出错: %v", err)
				}
				err = sess.WindowChange(height, width)
				if err != nil {
					return fmt.Errorf("改变窗口大小出错: %v", err)
				}
				t.Reset(500 * time.Millisecond)
			}
		}
	}()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1, //是否回显输入的命令
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := sess.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("创建终端出错: %v", err)
	}

	err = sess.Shell()
	if err != nil {
		return fmt.Errorf("执行Shell出错: %v", err)
	}

	err = sess.Wait()
	if err != nil {
		return nil // fmt.Errorf("执行Wait出错: %v", err)
	}
	return nil
}
