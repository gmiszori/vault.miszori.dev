package main

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

type BrowserProfile struct {
	Browser    string `json:"browser"`
	OS         string `json:"os"`
	DeviceType string `json:"deviceType"`
	UserAgent  string `json:"userAgent"`
}

func boundedUA(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	return strings.ToValidUTF8(s, "")
}

var hintBrand = regexp.MustCompile(`^"([^"\\\x00-\x1f]+)";\s*v="[0-9]{1,3}(?:\.[0-9]{1,3})*"$`)

func hintedBrowser(header string) string {
	if len(header) > 512 {
		return ""
	}
	brands := map[string]bool{}
	for _, part := range strings.Split(header, ",") {
		match := hintBrand.FindStringSubmatch(strings.TrimSpace(part))
		if match == nil {
			return ""
		}
		brands[match[1]] = true
	}
	for _, candidate := range []struct{ brand, browser string }{
		{"Microsoft Edge", "Edge"}, {"Opera", "Opera"}, {"Samsung Internet", "Samsung Internet"},
		{"Google Chrome", "Chrome"}, {"Firefox", "Firefox"}, {"Safari", "Safari"}, {"Chromium", "Chromium"},
	} {
		if brands[candidate.brand] {
			return candidate.browser
		}
	}
	return ""
}

// These are unverified, low-entropy request claims, not device identities.
func browserProfile(r *http.Request) *BrowserProfile {
	p := &BrowserProfile{Browser: "unknown", OS: "unknown", DeviceType: "unknown", UserAgent: boundedUA(r.Header.Get("User-Agent"))}
	ua := strings.ToLower(p.UserAgent)
	for _, candidate := range []struct {
		tokens  []string
		browser string
	}{
		{[]string{"edg/", "edga/", "edgios/", "edge/"}, "Edge"},
		{[]string{"opr/", "opera/", "opera ", "opios/"}, "Opera"},
		{[]string{"samsungbrowser/"}, "Samsung Internet"},
		{[]string{"firefox/", "fxios/"}, "Firefox"},
		{[]string{"chrome/", "crios/"}, "Chrome"},
		{[]string{"chromium/"}, "Chromium"},
	} {
		for _, token := range candidate.tokens {
			if strings.Contains(ua, token) {
				p.Browser = candidate.browser
				break
			}
		}
		if p.Browser != "unknown" {
			break
		}
	}
	if p.Browser == "unknown" && strings.Contains(ua, "safari/") && strings.Contains(ua, "version/") {
		p.Browser = "Safari"
	}
	switch {
	case strings.Contains(ua, "ipad"), strings.Contains(ua, "iphone"), strings.Contains(ua, "ipod"):
		p.OS = "iOS"
	case strings.Contains(ua, "android"):
		p.OS = "Android"
	case strings.Contains(ua, "windows nt"):
		p.OS = "Windows"
	case strings.Contains(ua, "cros"):
		p.OS = "Chrome OS"
	case strings.Contains(ua, "macintosh"), strings.Contains(ua, "mac os x"):
		p.OS = "macOS"
	case strings.Contains(ua, "linux"):
		p.OS = "Linux"
	}
	switch {
	case strings.Contains(ua, "ipad"), strings.Contains(ua, "tablet"), strings.Contains(ua, "kindle"), strings.Contains(ua, "silk/"), p.OS == "Android" && !strings.Contains(ua, "mobile"):
		p.DeviceType = "tablet"
	case strings.Contains(ua, "mobile"), strings.Contains(ua, "iphone"), strings.Contains(ua, "ipod"):
		p.DeviceType = "mobile"
	case p.OS == "Windows", p.OS == "macOS", p.OS == "Linux", p.OS == "Chrome OS":
		p.DeviceType = "desktop"
	}
	if browser := hintedBrowser(r.Header.Get("Sec-CH-UA")); browser != "" && (browser != "Chromium" || p.Browser == "unknown") {
		p.Browser = browser
	}
	if header := r.Header.Get("Sec-CH-UA-Platform"); len(header) <= 64 {
		if platform, err := strconv.Unquote(header); err == nil {
			switch platform {
			case "Windows", "macOS", "Linux", "Android", "iOS", "Chrome OS":
				p.OS = platform
			}
		}
	}
	if p.DeviceType != "tablet" {
		switch r.Header.Get("Sec-CH-UA-Mobile") {
		case "?1":
			p.DeviceType = "mobile"
		case "?0":
			p.DeviceType = "desktop"
		}
	}
	return p
}
