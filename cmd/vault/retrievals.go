package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const retrievalLogName = "retrievals.jsonl"
const maxRetrievalRecord = 16 * 1024

type Retrieval struct {
	OpenedAt      time.Time       `json:"openedAt"`
	OpenedIP      string          `json:"openedIp"`
	OpenedBrowser *BrowserProfile `json:"openedBrowser"`
}

type retrievalPage struct {
	Retrievals []auditRecord `json:"retrievals"`
	NextCursor string        `json:"nextCursor"`
}

func legacyRetrieval(p *Package) auditRecord {
	at := *p.OpenedAt
	return auditRecord{OpenedAt: &at, OpenedIP: p.OpenedIP, OpenedBrowser: p.OpenedBrowser}
}

func readRetrieval(reader *bufio.Reader) (auditRecord, int64, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		if len(line) > 0 && err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return auditRecord{}, 0, err
	}
	var record auditRecord
	err = json.Unmarshal(line, &record)
	if err == nil && !record.valid() {
		err = errors.New("invalid retrieval record")
	}
	return record, int64(len(line)), err
}

// Rebuild from the durable log rather than a metadata count that may lag a crash,
// noting whether plaintext records remain to be sealed.
func (s *Server) restoreRetrievalCount(p *Package) error {
	p.auditPlain, p.auditSealed = p.OpenedAt != nil, p.SealedRetrieval != nil
	f, err := os.Open(filepath.Join(s.dir(p.ID), retrievalLogName))
	if errors.Is(err, os.ErrNotExist) {
		if p.RetrievalCount > 1 || p.SealedRetrieval != nil {
			return errors.New("retrieval log missing")
		}
		p.RetrievalCount = 0
		if p.OpenedAt != nil {
			p.RetrievalCount = 1
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	expected := p.RetrievalCount
	p.RetrievalCount = 0
	reader := bufio.NewReaderSize(f, maxRetrievalRecord)
	for {
		record, _, err := readRetrieval(reader)
		if err == io.EOF {
			if p.RetrievalCount < expected {
				return errors.New("retrieval log truncated")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if record.SealedRecord != nil {
			p.auditSealed = true
		} else {
			p.auditPlain = true
		}
		p.RetrievalCount++
	}
}

// Called under s.mu. No ciphertext may be served until both file and directory sync succeed.
func (s *Server) appendRetrieval(p *Package, record auditRecord) error {
	if p.auditBroken {
		return errors.New("retrieval audit unavailable")
	}
	flags := os.O_APPEND | os.O_RDWR
	if p.RetrievalCount <= 1 {
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(filepath.Join(s.dir(p.ID), retrievalLogName), flags, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || (info.Size() == 0 && p.RetrievalCount > 1) {
		return errors.New("invalid retrieval log")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	added := int64(1)
	legacy := auditRecord{}
	if info.Size() == 0 && p.OpenedAt != nil {
		if legacy, err = s.sealRecord(p.ID, legacyRetrieval(p)); err != nil {
			return err
		}
		line, err := json.Marshal(legacy)
		if err != nil {
			return err
		}
		data = append(append(line, '\n'), data...)
		added++
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if err == nil {
		var dir *os.File
		dir, err = os.Open(s.dir(p.ID))
		if err == nil {
			err = dir.Sync()
			dir.Close()
		}
	}
	if err != nil {
		// Do not append behind a torn record if rollback itself cannot be made durable.
		if rollback := f.Truncate(info.Size()); rollback != nil {
			p.auditBroken = true
		} else if rollback = f.Sync(); rollback != nil {
			p.auditBroken = true
		}
		return err
	}
	if info.Size() == 0 {
		p.RetrievalCount = added
	} else {
		p.RetrievalCount += added
	}
	for _, written := range []auditRecord{legacy, record} {
		if written.SealedRecord != nil {
			p.auditSealed = true
		} else if written.OpenedAt != nil {
			p.auditPlain = true
		}
	}
	if err = f.Close(); err != nil {
		p.auditBroken = true
		return err
	}
	return nil
}

// The caller holds s.mu, so append/cleanup cannot change this bounded page while it is read.
func (s *Server) retrievals(w http.ResponseWriter, r *http.Request, p *Package) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(w, 400, "Invalid pagination")
		return
	}
	cursor := int64(0)
	if raw, ok := query["cursor"]; ok {
		if len(raw) != 1 {
			fail(w, 400, "Invalid cursor")
			return
		}
		cursor, err = strconv.ParseInt(raw[0], 10, 64)
		if err != nil || cursor < 0 || strconv.FormatInt(cursor, 10) != raw[0] {
			fail(w, 400, "Invalid cursor")
			return
		}
	}
	limit := 100
	if raw, ok := query["limit"]; ok {
		if len(raw) != 1 {
			fail(w, 400, "Invalid limit")
			return
		}
		limit, err = strconv.Atoi(raw[0])
		if err != nil || limit < 1 || limit > 100 {
			fail(w, 400, "Invalid limit")
			return
		}
	}
	page := retrievalPage{Retrievals: make([]auditRecord, 0, limit)}
	f, err := os.Open(filepath.Join(s.dir(p.ID), retrievalLogName))
	if errors.Is(err, os.ErrNotExist) {
		if p.RetrievalCount > 1 {
			fail(w, 500, "Audit unavailable")
			return
		}
		if cursor != 0 {
			fail(w, 400, "Invalid cursor")
			return
		}
		if p.OpenedAt != nil {
			page.Retrievals = append(page.Retrievals, legacyRetrieval(p))
		}
		writeJSON(w, 200, page)
		return
	}
	if err != nil {
		fail(w, 500, "Audit unavailable")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		fail(w, 500, "Audit unavailable")
		return
	}
	if cursor > info.Size() {
		fail(w, 400, "Invalid cursor")
		return
	}
	if cursor > 0 {
		var previous [1]byte
		if _, err = f.ReadAt(previous[:], cursor-1); err != nil || previous[0] != '\n' {
			fail(w, 400, "Invalid cursor")
			return
		}
	}
	if _, err = f.Seek(cursor, io.SeekStart); err != nil {
		fail(w, 500, "Audit unavailable")
		return
	}
	reader := bufio.NewReaderSize(f, maxRetrievalRecord)
	for len(page.Retrievals) < limit && cursor < info.Size() {
		record, size, err := readRetrieval(reader)
		if err != nil {
			fail(w, 500, "Audit unavailable")
			return
		}
		cursor += size
		page.Retrievals = append(page.Retrievals, record)
	}
	if cursor < info.Size() {
		page.NextCursor = strconv.FormatInt(cursor, 10)
	}
	writeJSON(w, 200, page)
}
