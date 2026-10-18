package main

import "os"

const maxTextBytes = 8 * 1024 * 1024
const maxTextManifestCiphertext = 1024 + 16
const maxTextPackageBytes int64 = maxTextBytes + 1024 + 32

func textRecordLimits(n int) (int64, int64) {
	if n == 0 {
		return 16, maxTextManifestCiphertext
	}
	return 17, maxTextBytes + 16
}

// Only ciphertext sizes are checked; manifest contents and UTF-8 validation stay client-side.
func (s *Server) validTextRecords(p *Package) (bool, error) {
	if p.Chunks != 2 || p.Bytes > maxTextPackageBytes {
		return false, nil
	}
	var total int64
	for n := 0; n < 2; n++ {
		info, err := os.Stat(s.chunk(p.ID, n))
		if err != nil {
			return false, err
		}
		min, max := textRecordLimits(n)
		if !info.Mode().IsRegular() || info.Size() < min || info.Size() > max {
			return false, nil
		}
		total += info.Size()
	}
	return total == p.Bytes, nil
}
