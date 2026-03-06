package services

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vultrack/vultrack/internal/config"
)

// Attachment represents an email attachment.
type Attachment struct {
	Filename    string
	ContentType string // e.g. "application/pdf"
	Data        []byte
}

// EmailService provides methods to send emails via SMTP.
type EmailService struct {
	enabled  bool
	host     string
	port     int
	user     string
	password string
	from     string
	tlsMode  string // "none", "starttls", "tls"
	heloHost string // EHLO/HELO hostname (default: OS hostname)
}

// NewEmailService creates a new EmailService from the application config.
func NewEmailService(cfg *config.Config) *EmailService {
	heloHost := cfg.SMTPHeloHost
	if heloHost == "" {
		heloHost, _ = os.Hostname()
	}
	if heloHost == "" {
		heloHost = "vultrack.local"
	}

	svc := &EmailService{
		enabled:  cfg.SMTPEnabled,
		host:     cfg.SMTPHost,
		port:     cfg.SMTPPort,
		user:     cfg.SMTPUser,
		password: cfg.SMTPPassword,
		from:     cfg.SMTPFrom,
		tlsMode:  strings.ToLower(cfg.SMTPTLSMode),
		heloHost: heloHost,
	}

	if svc.enabled {
		log.Info().
			Str("host", svc.host).
			Int("port", svc.port).
			Str("tls", svc.tlsMode).
			Str("helo", svc.heloHost).
			Bool("auth", svc.user != "").
			Msg("SMTP email service enabled")
	} else {
		log.Info().Msg("SMTP email service disabled")
	}

	return svc
}

// IsEnabled returns whether the email service is configured and enabled.
func (s *EmailService) IsEnabled() bool {
	return s.enabled
}

// SendEmail sends a plain-text and/or HTML email without attachments.
func (s *EmailService) SendEmail(to []string, subject, htmlBody, textBody string) error {
	return s.SendEmailWithAttachments(to, subject, htmlBody, textBody, nil)
}

// SendEmailWithAttachments sends an email with optional attachments.
// Both htmlBody and textBody can be provided; the mail client picks its preferred format.
// If only one body is provided, the other can be empty.
func (s *EmailService) SendEmailWithAttachments(to []string, subject, htmlBody, textBody string, attachments []Attachment) error {
	if !s.enabled {
		return fmt.Errorf("email service is not enabled")
	}
	if len(to) == 0 {
		return fmt.Errorf("no recipients specified")
	}
	if s.host == "" || s.from == "" {
		return fmt.Errorf("SMTP host or from address not configured")
	}

	msg, err := buildMessage(s.from, to, subject, htmlBody, textBody, attachments)
	if err != nil {
		return fmt.Errorf("failed to build email message: %w", err)
	}

	if err := s.send(to, msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Info().
		Strs("to", to).
		Str("subject", subject).
		Int("attachments", len(attachments)).
		Msg("Email sent successfully")

	return nil
}

// smtpTimeout is the timeout for SMTP dial and per-command operations.
const smtpTimeout = 30 * time.Second

// tlsConfig returns a TLS configuration with secure defaults.
func (s *EmailService) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName: s.host,
		MinVersion: tls.VersionTLS12,
	}
}

// send implements the full SMTP conversation manually (without Go's smtp.Client).
// Go's smtp.Client/smtp.Dial hardcodes "EHLO localhost" which many relays (Google,
// Microsoft, etc.) reject. By driving the protocol directly we control every step
// and produce detailed diagnostics at each phase.
func (s *EmailService) send(to []string, msg []byte) error {
	addr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))

	// ── Step 1: TCP / TLS connect ──────────────────────────────────────
	var conn net.Conn
	var err error

	if s.tlsMode == "tls" {
		dialer := &net.Dialer{Timeout: smtpTimeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, s.tlsConfig())
	} else {
		conn, err = net.DialTimeout("tcp", addr, smtpTimeout)
	}
	if err != nil {
		return fmt.Errorf("connect to %s failed: %w", addr, err)
	}
	defer conn.Close()

	// Per-command deadline; reset after each successful exchange.
	setDeadline := func() { conn.SetDeadline(time.Now().Add(smtpTimeout)) }
	setDeadline()

	tp := textproto.NewConn(conn)

	// ── Step 2: Read server banner (expect 220) ────────────────────────
	code, banner, err := tp.ReadResponse(220)
	if err != nil {
		return fmt.Errorf("server banner (code %d): %w", code, err)
	}
	log.Debug().Str("banner", banner).Msg("SMTP connected")

	// ── Step 3: EHLO ───────────────────────────────────────────────────
	setDeadline()
	extensions, err := smtpEHLO(tp, s.heloHost)
	if err != nil {
		return fmt.Errorf("EHLO %s: %w", s.heloHost, err)
	}

	// ── Step 4: STARTTLS (if configured or opportunistic) ──────────────
	if s.tlsMode == "starttls" {
		if _, ok := extensions["STARTTLS"]; !ok {
			return fmt.Errorf("server does not advertise STARTTLS (extensions: %v)", extensionKeys(extensions))
		}
		setDeadline()
		if err := smtpCmd(tp, 220, "STARTTLS"); err != nil {
			return fmt.Errorf("STARTTLS command rejected: %w", err)
		}

		// Upgrade the raw TCP connection to TLS
		tlsConn := tls.Client(conn, s.tlsConfig())
		setDeadline()
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("TLS handshake with %s failed: %w", s.host, err)
		}
		log.Debug().Str("version", tlsVersionString(tlsConn.ConnectionState().Version)).Msg("TLS established")

		// Wrap the TLS connection in a new textproto.Conn
		tp = textproto.NewConn(tlsConn)

		// Re-EHLO required after STARTTLS per RFC 3207
		setDeadline()
		extensions, err = smtpEHLO(tp, s.heloHost)
		if err != nil {
			return fmt.Errorf("EHLO after STARTTLS: %w", err)
		}
	} else if s.tlsMode == "none" {
		// Opportunistic STARTTLS on plain connections
		if _, ok := extensions["STARTTLS"]; ok {
			setDeadline()
			if err := smtpCmd(tp, 220, "STARTTLS"); err == nil {
				tlsConn := tls.Client(conn, s.tlsConfig())
				if err := tlsConn.Handshake(); err == nil {
					tp = textproto.NewConn(tlsConn)
					setDeadline()
					extensions, _ = smtpEHLO(tp, s.heloHost)
				} else {
					log.Warn().Err(err).Msg("Opportunistic TLS handshake failed, continuing unencrypted")
				}
			}
		}
	}

	// ── Step 5: AUTH PLAIN (optional) ──────────────────────────────────
	if s.user != "" {
		if _, ok := extensions["AUTH"]; !ok {
			return fmt.Errorf("server does not advertise AUTH (extensions: %v)", extensionKeys(extensions))
		}
		cred := base64.StdEncoding.EncodeToString([]byte("\x00" + s.user + "\x00" + s.password))
		setDeadline()
		if err := smtpCmd(tp, 235, "AUTH PLAIN %s", cred); err != nil {
			return fmt.Errorf("AUTH PLAIN failed: %w", err)
		}
	}

	// ── Step 6: MAIL FROM ──────────────────────────────────────────────
	from := extractAddress(s.from)
	setDeadline()
	if err := smtpCmd(tp, 250, "MAIL FROM:<%s>", from); err != nil {
		return fmt.Errorf("MAIL FROM <%s>: %w", from, err)
	}

	// ── Step 7: RCPT TO ────────────────────────────────────────────────
	for _, rcpt := range to {
		setDeadline()
		if err := smtpCmd(tp, 250, "RCPT TO:<%s>", rcpt); err != nil {
			return fmt.Errorf("RCPT TO <%s>: %w", rcpt, err)
		}
	}

	// ── Step 8: DATA ───────────────────────────────────────────────────
	setDeadline()
	if err := smtpCmd(tp, 354, "DATA"); err != nil {
		return fmt.Errorf("DATA: %w", err)
	}

	// Write message with dot-stuffing, terminated by ".\r\n"
	dw := tp.DotWriter()
	if _, err := dw.Write(msg); err != nil {
		return fmt.Errorf("write message body: %w", err)
	}
	if err := dw.Close(); err != nil {
		return fmt.Errorf("end message body: %w", err)
	}

	// Server responds with 250 after accepting the message
	setDeadline()
	if _, _, err := tp.ReadResponse(250); err != nil {
		return fmt.Errorf("message not accepted: %w", err)
	}

	// ── Step 9: QUIT ───────────────────────────────────────────────────
	setDeadline()
	_ = smtpCmd(tp, 221, "QUIT") // best-effort

	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// SMTP protocol helpers
// ────────────────────────────────────────────────────────────────────────────

// smtpCmd sends a single SMTP command and reads the response, expecting the given code.
func smtpCmd(tp *textproto.Conn, expectCode int, format string, args ...interface{}) error {
	id, err := tp.Cmd(format, args...)
	if err != nil {
		return err
	}
	tp.StartResponse(id)
	defer tp.EndResponse(id)
	_, _, err = tp.ReadResponse(expectCode)
	return err
}

// smtpEHLO sends EHLO and parses the extension list from the multiline 250 response.
func smtpEHLO(tp *textproto.Conn, hostname string) (map[string]string, error) {
	id, err := tp.Cmd("EHLO %s", hostname)
	if err != nil {
		return nil, err
	}
	tp.StartResponse(id)
	defer tp.EndResponse(id)

	code, msg, err := tp.ReadResponse(250)
	if err != nil {
		// Fall back to HELO (for very old servers)
		id2, err2 := tp.Cmd("HELO %s", hostname)
		if err2 != nil {
			return nil, fmt.Errorf("EHLO failed (code %d): %w", code, err)
		}
		tp.StartResponse(id2)
		defer tp.EndResponse(id2)
		if _, _, err2 := tp.ReadResponse(250); err2 != nil {
			return nil, fmt.Errorf("both EHLO and HELO failed: %w", err)
		}
		return map[string]string{}, nil
	}

	extensions := make(map[string]string)
	// Parse multiline response: each line after the first is an extension
	lines := strings.Split(msg, "\n")
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key := line
		val := ""
		if i := strings.IndexByte(line, ' '); i > 0 {
			key = line[:i]
			val = line[i+1:]
		}
		extensions[strings.ToUpper(key)] = val
	}

	return extensions, nil
}

// extensionKeys returns the keys of the extensions map for error messages.
func extensionKeys(exts map[string]string) []string {
	keys := make([]string, 0, len(exts))
	for k := range exts {
		keys = append(keys, k)
	}
	return keys
}

// tlsVersionString returns a human-readable TLS version string.
func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// buildMessage constructs a MIME email with optional HTML, plain-text, and attachments.
func buildMessage(from string, to []string, subject, htmlBody, textBody string, attachments []Attachment) ([]byte, error) {
	var buf bytes.Buffer

	// Top-level headers
	buf.WriteString("From: " + from + "\r\n")
	buf.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	buf.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")

	hasAttachments := len(attachments) > 0
	hasHTML := htmlBody != ""
	hasText := textBody != ""
	hasBothBodies := hasHTML && hasText

	if !hasAttachments && !hasBothBodies {
		// Simple single-part message
		if hasHTML {
			buf.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
			buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
			buf.WriteString(htmlBody)
		} else {
			buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
			buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
			buf.WriteString(textBody)
		}
		return buf.Bytes(), nil
	}

	// Multipart message
	if hasAttachments {
		// mixed boundary wraps alternative body + attachments
		mixedWriter := multipart.NewWriter(&buf)
		buf.WriteString("Content-Type: multipart/mixed; boundary=\"" + mixedWriter.Boundary() + "\"\r\n\r\n")

		// Body part (possibly multipart/alternative)
		if err := writeBodyParts(mixedWriter, htmlBody, textBody); err != nil {
			return nil, err
		}

		// Attachment parts
		for _, att := range attachments {
			if err := writeAttachment(mixedWriter, att); err != nil {
				return nil, err
			}
		}

		mixedWriter.Close()
	} else {
		// No attachments, but both HTML and text → multipart/alternative
		altWriter := multipart.NewWriter(&buf)
		buf.WriteString("Content-Type: multipart/alternative; boundary=\"" + altWriter.Boundary() + "\"\r\n\r\n")

		writeTextPart(altWriter, textBody)
		writeHTMLPart(altWriter, htmlBody)
		altWriter.Close()
	}

	return buf.Bytes(), nil
}

// writeBodyParts writes the text/HTML body into a multipart writer.
// If both are provided, it creates a nested multipart/alternative.
func writeBodyParts(w *multipart.Writer, htmlBody, textBody string) error {
	hasHTML := htmlBody != ""
	hasText := textBody != ""

	if hasHTML && hasText {
		// Nested multipart/alternative inside multipart/mixed
		var altBuf bytes.Buffer
		altWriter := multipart.NewWriter(&altBuf)

		header := make(textproto.MIMEHeader)
		header.Set("Content-Type", "multipart/alternative; boundary=\""+altWriter.Boundary()+"\"")
		part, err := w.CreatePart(header)
		if err != nil {
			return err
		}

		writeTextPart(altWriter, textBody)
		writeHTMLPart(altWriter, htmlBody)
		altWriter.Close()

		_, err = io.Copy(part, &altBuf)
		return err
	}

	if hasHTML {
		writeHTMLPart(w, htmlBody)
	} else if hasText {
		writeTextPart(w, textBody)
	}
	return nil
}

func writeTextPart(w *multipart.Writer, body string) {
	header := make(textproto.MIMEHeader)
	header.Set("Content-Type", "text/plain; charset=\"utf-8\"")
	header.Set("Content-Transfer-Encoding", "quoted-printable")
	part, _ := w.CreatePart(header)
	part.Write([]byte(body))
}

func writeHTMLPart(w *multipart.Writer, body string) {
	header := make(textproto.MIMEHeader)
	header.Set("Content-Type", "text/html; charset=\"utf-8\"")
	header.Set("Content-Transfer-Encoding", "quoted-printable")
	part, _ := w.CreatePart(header)
	part.Write([]byte(body))
}

func writeAttachment(w *multipart.Writer, att Attachment) error {
	contentType := att.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	header := make(textproto.MIMEHeader)
	header.Set("Content-Type", contentType+"; name=\""+filepath.Base(att.Filename)+"\"")
	header.Set("Content-Disposition", "attachment; filename=\""+filepath.Base(att.Filename)+"\"")
	header.Set("Content-Transfer-Encoding", "base64")

	part, err := w.CreatePart(header)
	if err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(att.Data)
	// Write in 76-char lines per RFC 2045
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		part.Write([]byte(encoded[i:end] + "\r\n"))
	}

	return nil
}

// extractAddress extracts the bare email address from a "Name <addr>" format.
func extractAddress(from string) string {
	if idx := strings.Index(from, "<"); idx >= 0 {
		end := strings.Index(from, ">")
		if end > idx {
			return from[idx+1 : end]
		}
	}
	return from
}
