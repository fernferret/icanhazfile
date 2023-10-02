package main

// An example file download server using wish!

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"strconv"
	"strings"

	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/scp"
	gossh "golang.org/x/crypto/ssh"
)

const (
	host = "0.0.0.0"
	port = 23235
)

type ICanHazHandler struct {
}

var errUnrecognizedKey = errors.New("public key not recognized by this server")

func authorizeUser(s ssh.Session) error {
	exampleKey, _, _, _, _ := ssh.ParseAuthorizedKey(
		[]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCqHiaXGzx4SMQl5rtYkkZjkKGdN9ckjB9SeaAGUQLuSTkqYctkd6UTHgfzi7Qp6iKM3rwRjcZqrt6L8Fc21GTEhsIpVCd3CMrvgbR+4b4pLn2kyLCYulvNzgaTpvARSb+BlGYE36HSSHHB5MKV9MTGvIAO+fMXy/EEGjOz8TUQv7YJpiuxWFn3A7Vtr0YsJqUnK3cdx0rbWEwFrMHaOGEAfx0GoHcH5iGWVktmPRFqTGf9yiEFtaL+od47K72aU01RR2S8faYKzFAMB2mbfDepkyOEmsvlcd+VkWDkbBtXujW5iXJAV1TCeX7kIptT4AIkHVC64OajAWtDwBEQi+Vf02ShbU2WVpHtDOmyGleH3qm+dEfq7ECFx0Kz5H/1ATOJyax4BLDqvhEAiOB8D/6LEGekBAzFVsJUfq0493Vb+UDCur3sgEu1s6YyE7XjX2poX1gBM7meICGQOpYEidIamFrtCNHkqJ20sIfXG94iIrZ//9Lfj2suA+kQYFYCvWE="),
	)
	switch {
	case ssh.KeysEqual(s.PublicKey(), exampleKey):
		return nil
	}
	return errUnrecognizedKey
}

func (hdlr *ICanHazHandler) Glob(session ssh.Session, path string) ([]string, error) {
	pubKey := session.PublicKey()
	llog := log.With("addr", session.RemoteAddr().String(), "user", session.User())
	if pubKey == nil {
		llog.Warn("User did not pass a public key, showing welcome message.")
		msg := `ERROR: You did not login using an ssh key.

See https://samaritan.example.com/magicfile to get setup!
`
		return nil, errors.New(msg)
	}

	if err := authorizeUser(session); err != nil {
		msg := fmt.Sprintf(`ERROR: Your public key certificate was not recognized!

See https://samaritan.example.com/magicfile to help you diagnose what went wrong!

The full error message was:
%s
`, err)
		return nil, errors.New(msg)
	}

	// Allow 8 randomly generated files
	maxFiles := 8

	// If the path was just a "." (or the "list" command) the user typed a command like:
	// scp  -P 23235 goose:list /tmp/
	if path == "." || strings.ToLower(path) == "list" {
		llog.Info("No file requested, displaying file list and exiting.")
		msgs := []string{}
		// max := int(rand.Float32() * float32(maxFiles))
		max := 4
		randItem := int(rand.Float32() * float32(max))
		for idx := 0; idx < max; idx++ {
			msgs = append(msgs, fmt.Sprintf("[%d] my_cool_files.zip ", idx))
		}
		msg := strings.Join(msgs, "\n")
		return nil, errors.New(msg + "\n" + fmt.Sprintf(`
Select a file to download from the list above.
As an example, you could download item #%d with
the following command:

  scp -i ~/.ssh/my_samaritan_key -P 23235 goose:%d /where/i/want/my/files/

`, randItem, randItem))
	}

	number, err := strconv.Atoi(path)
	if err != nil || number >= maxFiles {
		msg := fmt.Sprintf(`Sorry the file %q was not available for you.

Please go to samaritan and create a video
archive. This will give you the command
to run to download the archive.

For more help, go to https://samaritan.example.com/ssh_download
`, path)
		return nil, errors.New(msg)
	}

	llog.With("file", path).Info("Sending file to user")
	return []string{path}, nil
}

func (hdlr *ICanHazHandler) WalkDir(_ ssh.Session, path string, fn fs.WalkDirFunc) error {
	// No need for WalkDir for this example, it is required by the Interface.
	return nil
}

func (hdlr *ICanHazHandler) NewDirEntry(_ ssh.Session, name string) (*scp.DirEntry, error) {
	// No need for Dir Entries for this example, it is required by the Interface.
	return nil, nil
}

func (hdlr *ICanHazHandler) NewFileEntry(session ssh.Session, name string) (*scp.FileEntry, func() error, error) {
	llog := log.With("name", name, "user", session.User(), "addr", session.RemoteAddr())
	llog.Info("Serving file to user")
	myString := fmt.Sprintf("I am a file with the number %q in it!\n(and a second line and a trailing newline)\n", name)
	fileReader := strings.NewReader(myString)

	return &scp.FileEntry{
		Name:     name,
		Filepath: name,
		Reader:   fileReader,
		Mode:     fs.FileMode(0644),
		Size:     int64(len(myString)),
	}, nil, nil
}

func ICanHazFileHandler() scp.CopyToClientHandler {
	return &ICanHazHandler{}
}

func main() {
	fileHandler := ICanHazFileHandler()
	s, err := wish.NewServer(
		wish.WithAddress(fmt.Sprintf("%s:%d", host, port)),
		// TODO: Use a custom HostKey
		wish.WithHostKeyPath(".ssh/term_info_ed25519"),
		wish.WithMiddleware(
			scp.Middleware(fileHandler, nil),
		),
		wish.WithKeyboardInteractiveAuth(func(ctx ssh.Context, challenger gossh.KeyboardInteractiveChallenge) bool {
			// Always return true here, we want to show our own more helpful
			// error message, rather than "Permission denied
			// (keyboard-interactive)"
			//
			// The actual public key authentication will be performed in the
			// middleware, so we'll find out that there was no public key passed
			// and we'll return a helpful message to the user.
			return true
		}),
		wish.WithPublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			log.Debug("Using Key authentication")
			// Always return true here, we want to show our own more helpful
			// error message, rather than "Permission denied (publickey)"
			//
			// The actual public key authentication will be performed in the
			// middleware.
			return true
		}),
	)
	if err != nil {
		log.Error("could not start server", "error", err)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	log.Info("Starting SSH server", "host", host, "port", port)
	go func() {
		if err = s.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			log.Error("could not start server", "error", err)
			done <- nil
		}
	}()

	<-done
	log.Info("Stopping SSH server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer func() { cancel() }()
	if err := s.Shutdown(ctx); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		log.Error("could not stop server", "error", err)
	}
}
