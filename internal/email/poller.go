package email

import (
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/hootmeow/Vuln-Strix/internal/config"
	"github.com/hootmeow/Vuln-Strix/internal/ingest"
	"github.com/hootmeow/Vuln-Strix/internal/storage"
)

type Poller struct {
	cfg   config.EmailConfig
	store storage.Store
	stop  chan struct{}
}

func NewPoller(cfg config.EmailConfig, store storage.Store) *Poller {
	return &Poller{
		cfg:   cfg,
		store: store,
		stop:  make(chan struct{}),
	}
}

func (p *Poller) Start() {
	if !p.cfg.Enabled {
		return
	}

	go func() {
		ticker := time.NewTicker(time.Duration(p.cfg.PollInterval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := p.checkEmail(); err != nil {
					log.Printf("Email Poller Error: %v", err)
				}
			case <-p.stop:
				return
			}
		}
	}()
}

func (p *Poller) Stop() {
	close(p.stop)
}

func (p *Poller) checkEmail() error {
	log.Println("Checking for new emails...")

	// Connect to server
	addr := fmt.Sprintf("%s:%d", p.cfg.IMAPServer, p.cfg.IMAPPort)
	c, err := client.DialTLS(addr, nil)
	if err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	defer c.Logout()

	if err := c.Login(p.cfg.Username, p.cfg.Password); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	mbox, err := c.Select("INBOX", false)
	if err != nil {
		return fmt.Errorf("select inbox failed: %w", err)
	}

	if mbox.Messages == 0 {
		return nil // No messages
	}

	// Search for UNSEEN messages
	criteria := imap.NewSearchCriteria()
	criteria.WithoutFlags = []string{imap.SeenFlag}
	uids, err := c.Search(criteria)
	if err != nil {
		return err
	}
	if len(uids) == 0 {
		return nil
	}

	seqset := new(imap.SeqSet)
	seqset.AddNum(uids...)

	// Fetch body
	section := &imap.BodySectionName{}
	items := []imap.FetchItem{section.FetchItem()}

	messages := make(chan *imap.Message)
	done := make(chan error, 1)
	go func() {
		done <- c.Fetch(seqset, items, messages)
	}()

	for msg := range messages {
		r := msg.GetBody(section)
		if r == nil {
			continue
		}

		if err := p.processMessage(r); err != nil {
			log.Printf("Failed to process message: %v", err)
		} else {
			// Mark as processed (or move folder, but here we just leave it marked as SEEN by default fetch behavior if we didn't use Peek)
			// Actually, fetching without Peek AUTOMATICALLY marks as Seen.
			// So we don't need to do extra work unless we want to move it.
		}
	}

	return <-done
}

func (p *Poller) processMessage(r io.Reader) error {
	m, err := mail.ReadMessage(r)
	if err != nil {
		return err
	}

	contentType := m.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return err
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(m.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			filename := part.FileName()
			if filename == "" {
				continue
			}

			if strings.HasSuffix(strings.ToLower(filename), ".nessus") || strings.HasSuffix(strings.ToLower(filename), ".csv") {
				if err := p.downloadAndIngest(part, filename); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (p *Poller) downloadAndIngest(r io.Reader, filename string) error {
	tmpFile, err := os.CreateTemp("", "vuln-strix-*"+filename)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, r); err != nil {
		return err
	}

	log.Printf("Downloaded attachment: %s", filename)
	
	// Rewind file or just pass path (ProcessFile takes path)
	if err := ingest.ProcessFile(p.store, tmpFile.Name()); err != nil {
		return err
	}
	
	return nil
}
