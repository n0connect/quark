// Method 2 ("protect a program at the source level"), Go, via cgo.
//
// This program's own source calls quark_c_api directly -- no external
// DRM_Wrapper process, no pipe protocol. The protection is embedded in this
// program's own code: it runs the full unlock flow itself
// (quark_unlock_and_decrypt) and only proceeds using whatever bytes come
// back. A wrong key, wrong machine, or tampered state.bin makes this call
// fail closed -- there is no separate "licensed?" boolean anywhere in this
// file to patch.
package main

/*
#cgo LDFLAGS: -lquark_c
#include <stdlib.h>
#include "quark_c_api.h"
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

func main() {
	if len(os.Args) != 9 {
		fmt.Fprintln(os.Stderr, "usage: method2_embedded <state_path> <build_secret> <unlock_key_hex> "+
			"<sealed_payload_path> <witness_host_path> <witness_file_path> <xattr1_attr> <xattr2_attr>")
		os.Exit(2)
	}
	statePath := os.Args[1]
	buildSecret := os.Args[2]
	unlockKey := os.Args[3]
	sealedPath := os.Args[4]
	witnessHost := os.Args[5]
	witnessFile := os.Args[6]
	attr1 := os.Args[7]
	attr2 := os.Args[8]

	sealed, err := os.ReadFile(sealedPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read sealed payload:", err)
		os.Exit(1)
	}

	cStatePath := C.CString(statePath)
	defer C.free(unsafe.Pointer(cStatePath))
	cBuildSecret := C.CString(buildSecret)
	defer C.free(unsafe.Pointer(cBuildSecret))
	cKey := C.CString(unlockKey)
	defer C.free(unsafe.Pointer(cKey))
	cWitnessHost := C.CString(witnessHost)
	defer C.free(unsafe.Pointer(cWitnessHost))
	cWitnessFile := C.CString(witnessFile)
	defer C.free(unsafe.Pointer(cWitnessFile))
	cAttr1 := C.CString(attr1)
	defer C.free(unsafe.Pointer(cAttr1))
	cAttr2 := C.CString(attr2)
	defer C.free(unsafe.Pointer(cAttr2))

	var witnesses [3]C.quark_witness_channel_t

	witnesses[0].kind = C.QUARK_WITNESS_KIND_XATTR
	witnesses[0].path = cWitnessHost
	witnesses[0].attr_name = cAttr1
	witnesses[0].magic[0] = 'Q'
	witnesses[0].magic[1] = 'W'
	witnesses[0].magic[2] = 'X'
	witnesses[0].magic[3] = '1'

	witnesses[1].kind = C.QUARK_WITNESS_KIND_XATTR
	witnesses[1].path = cWitnessHost
	witnesses[1].attr_name = cAttr2
	witnesses[1].magic[0] = 'Q'
	witnesses[1].magic[1] = 'W'
	witnesses[1].magic[2] = 'X'
	witnesses[1].magic[3] = '2'

	witnesses[2].kind = C.QUARK_WITNESS_KIND_FILE
	witnesses[2].path = cWitnessFile
	witnesses[2].magic[0] = 'Q'
	witnesses[2].magic[1] = 'W'
	witnesses[2].magic[2] = 'F'
	witnesses[2].magic[3] = '0'

	plaintext := make([]byte, 4096)
	var plainLen C.size_t

	rc := C.quark_unlock_and_decrypt(
		cStatePath, cBuildSecret,
		&witnesses[0],
		cKey,
		(*C.uint8_t)(unsafe.Pointer(&sealed[0])), C.size_t(len(sealed)),
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		&plainLen,
		nil, nil,
	)

	if rc != C.QUARK_OK {
		desc := C.GoString(C.quark_error_describe(rc))
		fmt.Fprintf(os.Stderr, "quark_unlock_and_decrypt failed: %d (%s)\n", int32(rc), desc)
		os.Exit(1)
	}

	os.Stdout.Write(plaintext[:plainLen])
}
