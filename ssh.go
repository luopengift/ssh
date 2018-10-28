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
// !! users, passwords 仅在登陆认证时当user/password字段为空时使用
type Endpoint struct {
	Name      string            `yaml:"name"`
	Host      string            `yaml:"host"`
	IP        string            `yaml:"ip"`
	Port      string            `yaml:"port"`
	User      string            `yaml:"user"`
	Users     []string          `yaml:"users"` // 多个用户
	Password  string            `yaml:"password"`
	Passwords []string          `yaml:"passwords"` //密码列表
	Key       string            `yaml:"key"`
	QAs       map[string]string `yaml:"qas"`    //questions-answers
	Pseudo    bool              `yaml:"pseudo"` // like "ssh -tt", Force pseudo-terminal allocation.
	Timeout   int               `yaml:"timeout"`
	Labels    map[string]string `yaml:"labels"`
	writers   []io.Writer       // this is used for screen stream copy or backup

	client *ssh.Client `yaml:"-"`
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

// SetPseudo disable/force pseudo-terminal allocation.
func (ep *Endpoint) SetPseudo(pseudo bool) {
	ep.Pseudo = pseudo
}

// SetUsers set multi-user
func (ep *Endpoint) SetUsers(users ...string) {
	ep.Users = users
}

// SetPasswords set multi-password
func (ep *Endpoint) SetPasswords(passwords ...string) {
	ep.Passwords = passwords
}

// SetTimeout SetTimeout
func (ep *Endpoint) SetTimeout(timeout int) {
	ep.Timeout = timeout
}

// SetWriters this method is useful in StartTerminal
func (ep *Endpoint) SetWriters(writers ...io.Writer) {
	ep.writers = writers
}

// GetUsers get users list
// if user is not null, then return user directly
func (ep *Endpoint) GetUsers() ([]string, bool) {
	if ep.User != "" {
		return []string{ep.User}, true
	}
	return ep.Users, false
}

// GetPasswords get passwords list
// if password is not null, then return password directly
func (ep *Endpoint) GetPasswords() ([]string, bool) {
	if ep.Password != "" {
		return []string{ep.Password}, true
	}
	return ep.Passwords, false
}

// Copy copy a endpoint
func (ep *Endpoint) Copy() *Endpoint {
	endpoint := NewEndpoint()
	endpoint.Name = ep.Name
	endpoint.Host = ep.Host
	endpoint.IP = ep.IP
	endpoint.Port = ep.Port
	endpoint.User = ep.User
	endpoint.Users = append(endpoint.Users, ep.Users...)
	endpoint.Password = ep.Password
	endpoint.Passwords = append(endpoint.Users, ep.Passwords...)
	endpoint.Key = ep.Key
	endpoint.QAs = ep.QAs
	endpoint.Pseudo = ep.Pseudo
	endpoint.Timeout = ep.Timeout
	endpoint.Labels = ep.Labels
	endpoint.writers = ep.writers
	return endpoint
}

// Mask endpoint, 优先级从高到底, 如果之前的有值那么后面的默认忽略掉
func (ep *Endpoint) Mask(endpoints ...*Endpoint) {
	for _, endpoint := range endpoints {
		if ep.Name == "" {
			ep.Name = endpoint.Name
		}
		if ep.Host == "" {
			ep.Host = endpoint.Host
		}
		if ep.IP == "" {
			ep.IP = endpoint.IP
		}
		if ep.Port == "" {
			ep.Port = endpoint.Port
		}
		if ep.User == "" && len(ep.Users) == 0 {
			ep.User = endpoint.User
		}
		if len(ep.Users) == 0 {
			ep.Users = append(ep.Users, endpoint.Users...)
		}
		if ep.Password == "" && len(ep.Passwords) == 0 {
			ep.Password = endpoint.Password
		}
		if len(ep.Passwords) == 0 {
			ep.Passwords = append(ep.Passwords, endpoint.Passwords...)
		}
		if ep.Key == "" {
			ep.Key = endpoint.Key
		}
		if ep.QAs == nil {
			ep.QAs = endpoint.QAs
		}
		if !ep.Pseudo {
			ep.Pseudo = endpoint.Pseudo
		}
		if ep.Timeout == 0 {
			ep.Timeout = endpoint.Timeout
		}
	}
}

// 解析登录方式
func (ep *Endpoint) authMethods() (authMethods []ssh.AuthMethod, err error) {
	passwords, _ := ep.GetPasswords()

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
func (ep *Endpoint) InitSSHClient() (err error) {
	if ep.client != nil {
		return nil
	}
	users, _ := ep.GetUsers()

	for _, user := range users {
		var auths []ssh.AuthMethod
		auths, err = ep.authMethods()
		if err != nil {
			return fmt.Errorf("鉴权出错: %v", err)
		}

		config := &ssh.ClientConfig{
			User:            user,
			Auth:            auths,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         time.Duration(ep.Timeout) * time.Second,
		}

		if ep.client, err = ssh.Dial("tcp", ep.Address(), config); err == nil {
			return nil
		}
	}
	return err
}

// Upload Upload
func (ep *Endpoint) Upload(src, dest string, mode os.FileMode) error {
	if err := ep.InitSSHClient(); err != nil {
		return fmt.Errorf("建立ssh连接出错: %v", err)
	}

	sftpClient, err := sftp.NewClient(ep.client)
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
	return destFile.Chmod(mode)
}

// Download Download
func (ep *Endpoint) Download(src, dest string) error {
	if err := ep.InitSSHClient(); err != nil {
		return fmt.Errorf("建立ssh连接出错: %v", err)
	}
	sftpClient, err := sftp.NewClient(ep.client)
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
	if err := ep.InitSSHClient(); err != nil {
		return nil, fmt.Errorf("建立SSH连接出错: %v", err)
	}
	sess, err := ep.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("创建Session出错: %v", err)
	}
	defer sess.Close()
	if ep.Pseudo {
		// Set up terminal modes
		modes := ssh.TerminalModes{
			ssh.ECHO:          1, //是否回显输入的命令
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		// Request pseudo terminal
		if err = sess.RequestPty("xterm-256color", 0, 0, modes); err != nil {
			return nil, fmt.Errorf("创建终端出错: %v", err)
		}
	}
	return sess.CombinedOutput(cmd)
}

// StartTerminal StartTerminal
func (ep *Endpoint) StartTerminal() error {
	if err := ep.InitSSHClient(); err != nil {
		return fmt.Errorf("建立SSH连接出错: %v", err)
	}
	sess, err := ep.client.NewSession()
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
				if err = sess.WindowChange(height, width); err != nil {
					return fmt.Errorf("改变窗口大小出错: %v", err)
				}
				t.Reset(500 * time.Millisecond)
			}
		}
	}()
	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1, //是否回显输入的命令
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	// Request pseudo terminal
	if err = sess.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("创建终端出错: %v", err)
	}
	// Set up terminal modes
	if err = sess.Shell(); err != nil {
		return fmt.Errorf("执行Shell出错: %v", err)
	}

	return sess.Wait()
}

// Close close endpoint client
func (ep *Endpoint) Close() error {
	if ep.client != nil {
		return ep.client.Close()
	}
	return nil
}

// Find querys in endpoint
func (ep *Endpoint) Find(querys ...string) bool {
	for _, query := range querys {
		if strings.Contains(ep.Name, query) || strings.Contains(ep.Host, query) || strings.Contains(ep.IP, query) {
			return true
		}
	}
	return false
}
