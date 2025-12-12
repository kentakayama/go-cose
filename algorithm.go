package cose

import (
	"crypto"
	"strconv"
)

// Signature algorithms supported by this library.
//
// When using an algorithm which requires hashing,
// make sure the associated hash function is linked to the binary.
const (
	// RSASSA-PSS w/ SHA-256 by RFC 8230.
	// Requires an available crypto.SHA256.
	AlgorithmPS256 Algorithm = -37

	// RSASSA-PSS w/ SHA-384 by RFC 8230.
	// Requires an available crypto.SHA384.
	AlgorithmPS384 Algorithm = -38

	// RSASSA-PSS w/ SHA-512 by RFC 8230.
	// Requires an available crypto.SHA512.
	AlgorithmPS512 Algorithm = -39

	// ECDSA w/ SHA-256 by RFC 8152.
	// Requires an available crypto.SHA256.
	//
	// Deprecated: ONLY IF you aware that the recipient supports
	// [AlgorithmESP256], use it instead. Otherwise,
	// keep use [AlgorithmES256] for backward compatibility.
	AlgorithmES256 Algorithm = -7

	// ECDSA using P-256 curve and SHA-256 by RFC 9864.
	// Requires an available crypto.SHA256.
	AlgorithmESP256 Algorithm = -9

	// ECDSA w/ SHA-384 by RFC 8152.
	// Requires an available crypto.SHA384.
	//
	// Deprecated: ONLY IF you aware that the recipient supports
	// [AlgorithmESP384], use it instead. Otherwise,
	// keep use [AlgorithmES384] for backward compatibility.
	AlgorithmES384 Algorithm = -35

	// ECDSA using P-384 curve and SHA-384 by RFC 9864.
	// Requires an available crypto.SHA384.
	AlgorithmESP384 Algorithm = -51

	// ECDSA w/ SHA-512 by RFC 8152.
	// Requires an available crypto.SHA512.
	//
	// Deprecated: ONLY IF you aware that the recipient supports
	// [AlgorithmESP512], use it instead. Otherwise,
	// keep use [AlgorithmES512] for backward compatibility.
	AlgorithmES512 Algorithm = -36

	// ECDSA using P-521 curve and SHA-512 by RFC 9864.
	// Requires an available crypto.SHA512.
	AlgorithmESP512 Algorithm = -52

	// EdDSA using the Ed25519 parameter (Curve25519) by RFC 9864.
	AlgorithmEd25519EdDSA Algorithm = -19

	// PureEdDSA by RFC 8152.
	//
	// Deprecated: use [AlgorithmEdDSA] instead, which has
	// the same value but with a more accurate name.
	// ONLY IF you aware that the recipient supports
	// [AlgorithmEd25519EdDSA] (-19), use it instead. Otherwise,
	// keep use [AlgorithmEdDSA] for backward compatibility.
	AlgorithmEd25519 Algorithm = -8

	// PureEdDSA by RFC 8152.
	//
	// Deprecated: ONLY IF you aware that the recipient supports
	// [AlgorithmEd25519EdDSA] (-19), use it instead. Otherwise,
	// keep use [AlgorithmEdDSA] for backward compatibility.
	AlgorithmEdDSA Algorithm = -8
)

// Signature algorithms known, but not supported by this library.
//
// Signers and Verifiers requiring the algorithms below are not
// directly supported by this library. They need to be provided
// as an external [Signer] or [Verifier] implementation.
//
// An example use case where RS256 is allowed and used is in
// WebAuthn: https://www.w3.org/TR/webauthn-2/#sctn-sample-registration.
const (
	// RSASSA-PKCS1-v1_5 using SHA-256 by RFC 8812.
	AlgorithmRS256 Algorithm = -257

	// RSASSA-PKCS1-v1_5 using SHA-384 by RFC 8812.
	AlgorithmRS384 Algorithm = -258

	// RSASSA-PKCS1-v1_5 using SHA-512 by RFC 8812.
	AlgorithmRS512 Algorithm = -259
)

// Hash algorithms by RFC 9054.
const (
	// SHA-256 by RFC 9054.
	AlgorithmSHA256 Algorithm = -16

	// SHA-384 by RFC 9054.
	AlgorithmSHA384 Algorithm = -43

	// SHA-512 by RFC 9054.
	AlgorithmSHA512 Algorithm = -44
)

// AlgorithmReserved represents a reserved algorithm value by RFC 9053.
const AlgorithmReserved Algorithm = 0

// Algorithm represents an IANA algorithm entry in the COSE Algorithms registry.
//
// # See Also
//
// COSE Algorithms: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
//
// RFC 8152 section 16.4: https://datatracker.ietf.org/doc/html/rfc8152#section-16.4
type Algorithm int64

// String returns the name of the algorithm
func (a Algorithm) String() string {
	switch a {
	case AlgorithmPS256:
		return "PS256"
	case AlgorithmPS384:
		return "PS384"
	case AlgorithmPS512:
		return "PS512"
	case AlgorithmRS256:
		return "RS256"
	case AlgorithmRS384:
		return "RS384"
	case AlgorithmRS512:
		return "RS512"
	case AlgorithmES256:
		return "ES256"
	case AlgorithmESP256:
		return "ESP256"
	case AlgorithmES384:
		return "ES384"
	case AlgorithmESP384:
		return "ESP384"
	case AlgorithmES512:
		return "ES512"
	case AlgorithmESP512:
		return "ESP512"
	case AlgorithmEdDSA:
		// As stated in RFC 8152 section 8.2, only the pure EdDSA version is
		// used for COSE.
		return "EdDSA"
	case AlgorithmEd25519EdDSA:
		// As stated in RFC 8152 section 8.2, only the pure EdDSA version is
		// used for COSE.
		return "Ed25519"
	case AlgorithmReserved:
		return "Reserved"
	case AlgorithmSHA256:
		return "SHA-256"
	case AlgorithmSHA384:
		return "SHA-384"
	case AlgorithmSHA512:
		return "SHA-512"
	default:
		return "Algorithm(" + strconv.FormatInt(int64(a), 10) + ")"
	}
}

// hashFunc returns the hash associated with the algorithm supported by this
// library.
func (a Algorithm) hashFunc() crypto.Hash {
	switch a {
	case AlgorithmPS256, AlgorithmES256, AlgorithmESP256, AlgorithmSHA256:
		return crypto.SHA256
	case AlgorithmPS384, AlgorithmES384, AlgorithmESP384, AlgorithmSHA384:
		return crypto.SHA384
	case AlgorithmPS512, AlgorithmES512, AlgorithmESP512, AlgorithmSHA512:
		return crypto.SHA512
	default:
		return 0
	}
}

// computeHash computes the digest using the hash specified in the algorithm.
func (a Algorithm) computeHash(data []byte) ([]byte, error) {
	return computeHash(a.hashFunc(), data)
}

// computeHash computes the digest using the given hash.
func computeHash(h crypto.Hash, data []byte) ([]byte, error) {
	if !h.Available() {
		return nil, ErrUnavailableHashFunc
	}
	hh := h.New()
	if _, err := hh.Write(data); err != nil {
		return nil, err
	}
	return hh.Sum(nil), nil
}
