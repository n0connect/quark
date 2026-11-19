// Method 1 ("protect an already-written program"), Go, no cgo.
//
// DRM_Wrapper is generic about what it launches: its `jvm_path`/`jvm_args`
// config keys just name an executable to spawn and speak the QKH2 protocol
// with over two anonymous pipes (see docs/HANDOFF_PROTOCOL.md). Historically
// that executable is a JVM running quark.jar; here it is this plain Go
// binary instead. DRM_Wrapper does not know or care -- it only cares that
// whatever is on the other end of the pipe reads a 136-byte initial frame,
// then answers 40-byte challenge frames with the right 32-byte HMAC.
//
// This program deliberately avoids cgo/quark-runtime-c: it re-implements the
// QKH2 client wire format directly from docs/HANDOFF_PROTOCOL.md using only
// Go's standard crypto/sha256 + crypto/hmac, which is the strongest possible
// demonstration that the protocol is genuinely language-agnostic -- a
// from-scratch implementation in a language Quark's C++ core has never heard
// of interoperates with the real DRM_Wrapper binary with zero shared code.
//
// The program's own "protected logic" is a checkpoint-style token derived
// from content_key (mirrors quark_checkpoint()/@QuarkCheckpoint): a wrong or
// absent content_key would produce a different token, not a crash or a
// boolean -- the same anti-boolean-trap property CLAUDE.md requires
// everywhere else.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	initFrameSize = 136
	chalFrameSize = 40
)

func readExact(r io.Reader, n int) []byte {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		os.Exit(1) // parent died or protocol violated -- mirror halt(-1)
	}
	return buf
}

// content_key = SHA256("QUARK-CORE-CONTENT-KEY" || handoff_secret)
func deriveContentKey(handoffSecret []byte) []byte {
	h := sha256.New()
	h.Write([]byte("QUARK-CORE-CONTENT-KEY"))
	h.Write(handoffSecret)
	return h.Sum(nil)
}

func leU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// token = HMAC-SHA256(content_key, "CP" || id(u32-LE) || counter(u32-LE))[:8], little-endian
func checkpoint(contentKey []byte, id, counter uint32) int64 {
	msg := append([]byte("CP"), leU32(id)...)
	msg = append(msg, leU32(counter)...)
	mac := hmac.New(sha256.New, contentKey)
	mac.Write(msg)
	sum := mac.Sum(nil)
	return int64(binary.LittleEndian.Uint64(sum[:8]))
}

// response = HMAC-SHA256(content_key, "RESP" || session_id || counter(u32-LE) || nonce)
func challengeResponse(contentKey, sessionID []byte, counter uint32, nonce []byte) []byte {
	msg := append([]byte("RESP"), sessionID...)
	msg = append(msg, leU32(counter)...)
	msg = append(msg, nonce...)
	mac := hmac.New(sha256.New, contentKey)
	mac.Write(msg)
	return mac.Sum(nil)
}

func main() {
	frame := readExact(os.Stdin, initFrameSize)

	if !bytes.Equal(frame[0:4], []byte("QKH2")) {
		fmt.Fprintln(os.Stderr, "quark-go-method1: bad magic")
		os.Exit(1)
	}
	if version := binary.LittleEndian.Uint32(frame[4:8]); version != 2 {
		fmt.Fprintln(os.Stderr, "quark-go-method1: unsupported version", version)
		os.Exit(1)
	}

	handoffSecret := frame[8:40]
	sessionID := append([]byte(nil), frame[40:72]...)
	// frame[72:104] = initial_seal -- not independently re-derived here,
	// matching quark.jar's own documented behavior (HANDOFF_PROTOCOL.md §6).
	// frame[104:136] = core_enc_key -- unused; this demo has no core.enc.

	contentKey := deriveContentKey(handoffSecret)

	token := checkpoint(contentKey, 0x0001, 0)
	fmt.Fprintf(os.Stderr, "CHECKPOINT_RESULT=%d\n", token)

	counter := uint32(0)
	for {
		chal := readExact(os.Stdin, chalFrameSize)
		if !bytes.Equal(chal[0:4], []byte("CHAL")) {
			os.Exit(1)
		}
		frameCounter := binary.LittleEndian.Uint32(chal[4:8])
		nonce := chal[8:40]

		resp := challengeResponse(contentKey, sessionID, frameCounter, nonce)
		if _, err := os.Stdout.Write(resp); err != nil {
			os.Exit(1)
		}
		counter++
	}
}
