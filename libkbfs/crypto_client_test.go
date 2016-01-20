package libkbfs

import (
	"fmt"
	"testing"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/logger"
	keybase1 "github.com/keybase/client/go/protocol"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/context"
)

type FakeCryptoClient struct {
	Local   *CryptoLocal
	ctlChan chan struct{}
}

func NewFakeCryptoClient(config Config, signingKey SigningKey,
	cryptPrivateKey CryptPrivateKey, ctlChan chan struct{}) *FakeCryptoClient {
	return &FakeCryptoClient{
		Local:   NewCryptoLocal(config, signingKey, cryptPrivateKey),
		ctlChan: ctlChan,
	}
}

func (fc FakeCryptoClient) maybeWaitOnChannel() {
	if fc.ctlChan != nil {
		// say we're ready, and wait for the signal to proceed
		fc.ctlChan <- struct{}{}
		<-fc.ctlChan
	}
}

func (fc FakeCryptoClient) Call(_ context.Context, s string, args interface{}, res interface{}) error {
	switch s {
	case "keybase.1.crypto.signED25519":
		fc.maybeWaitOnChannel()
		arg := args.([]interface{})[0].(keybase1.SignED25519Arg)
		sigInfo, err := fc.Local.Sign(context.Background(), arg.Msg)
		if err != nil {
			return err
		}
		sigRes := res.(*keybase1.ED25519SignatureInfo)
		// Normally, we'd have to validate all the parameters
		// in sigInfo, but since this is used in tests only,
		// there's no need.
		var ed25519Signature keybase1.ED25519Signature
		copy(ed25519Signature[:], sigInfo.Signature)
		publicKey :=
			libkb.KIDToNaclSigningKeyPublic(sigInfo.VerifyingKey.kid.ToBytes())
		*sigRes = keybase1.ED25519SignatureInfo{
			Sig:       ed25519Signature,
			PublicKey: keybase1.ED25519PublicKey(*publicKey),
		}
		return nil

	case "keybase.1.crypto.unboxBytes32":
		fc.maybeWaitOnChannel()
		arg := args.([]interface{})[0].(keybase1.UnboxBytes32Arg)
		publicKey := MakeTLFEphemeralPublicKey(arg.PeersPublicKey)
		encryptedClientHalf := EncryptedTLFCryptKeyClientHalf{
			Version:       EncryptionSecretbox,
			EncryptedData: arg.EncryptedBytes32[:],
			Nonce:         arg.Nonce[:],
		}
		clientHalf, err := fc.Local.DecryptTLFCryptKeyClientHalf(
			context.Background(), publicKey, encryptedClientHalf)
		if err != nil {
			return err
		}
		res := res.(*keybase1.Bytes32)
		*res = clientHalf.data
		return nil

	case "keybase.1.crypto.unboxBytes32Any":
		fc.maybeWaitOnChannel()
		arg := args.([]interface{})[0].(keybase1.UnboxBytes32AnyArg)
		keys := make([]EncryptedTLFCryptKeyClientAndEphemeral, 0, len(arg.Bundles))
		for _, k := range arg.Bundles {
			ePublicKey := MakeTLFEphemeralPublicKey(k.PublicKey)
			encryptedClientHalf := EncryptedTLFCryptKeyClientHalf{
				Version:       EncryptionSecretbox,
				EncryptedData: make([]byte, len(k.Ciphertext)),
				Nonce:         make([]byte, len(k.Nonce)),
			}
			copy(encryptedClientHalf.EncryptedData, k.Ciphertext[:])
			copy(encryptedClientHalf.Nonce, k.Nonce[:])
			keys = append(keys, EncryptedTLFCryptKeyClientAndEphemeral{
				EPubKey:    ePublicKey,
				ClientHalf: encryptedClientHalf,
				PubKey:     MakeCryptPublicKey(k.Kid),
			})
		}
		clientHalf, index, err := fc.Local.DecryptTLFCryptKeyClientHalfAny(
			context.Background(), keys)
		if err != nil {
			return err
		}
		res := res.(*keybase1.UnboxAnyRes)
		res.Plaintext = clientHalf.data
		res.Index = index
		res.Kid = keys[index].PubKey.kidContainer.kid
		return nil

	default:
		return fmt.Errorf("Unknown call: %s %v %v", s, args, res)
	}
}

func testCryptoClientConfig(t *testing.T) Config {
	config := &ConfigLocal{codec: NewCodecMsgpack()}
	setTestLogger(config, t)
	return config
}

// Test that signing a message and then verifying it works.
func TestCryptoClientSignAndVerify(t *testing.T) {
	signingKey := MakeFakeSigningKeyOrBust("client sign")
	cryptPrivateKey := MakeFakeCryptPrivateKeyOrBust("client crypt private")
	config := testCryptoClientConfig(t)
	fc := NewFakeCryptoClient(config, signingKey, cryptPrivateKey, nil)
	c := newCryptoClientWithClient(config.Codec(), fc, logger.NewTestLogger(t))

	msg := []byte("message")
	sigInfo, err := c.Sign(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}

	err = c.Verify(msg, sigInfo)
	if err != nil {
		t.Error(err)
	}
}

// Test that canceling a signing RPC returns the correct error
func TestCryptoClientSignCanceled(t *testing.T) {
	signingKey := MakeFakeSigningKeyOrBust("client sign")
	cryptPrivateKey := MakeFakeCryptPrivateKeyOrBust("client crypt private")
	config := testCryptoClientConfig(t)
	ctlChan := make(chan struct{})
	fc := NewFakeCryptoClient(config, signingKey, cryptPrivateKey, ctlChan)
	c := newCryptoClientWithClient(config.Codec(), cancelableClient{fc}, logger.NewTestLogger(t))

	f := func(ctx context.Context) error {
		msg := []byte("message")
		_, err := c.Sign(ctx, msg)
		return err
	}
	testWithCanceledContext(t, context.Background(), ctlChan, ctlChan, f)
}

// Test that decrypting an TLF crypt key client half encrypted with
// box.Seal works.
func TestCryptoClientDecryptTLFCryptKeyClientHalfBoxSeal(t *testing.T) {
	signingKey := MakeFakeSigningKeyOrBust("client sign")
	cryptPrivateKey := MakeFakeCryptPrivateKeyOrBust("client crypt private")
	config := testCryptoClientConfig(t)
	fc := NewFakeCryptoClient(config, signingKey, cryptPrivateKey, nil)
	c := newCryptoClientWithClient(config.Codec(), fc, logger.NewTestLogger(t))

	_, _, ephPublicKey, ephPrivateKey, cryptKey, err := c.MakeRandomTLFKeys()
	if err != nil {
		t.Fatal(err)
	}

	serverHalf, err := c.MakeRandomTLFCryptKeyServerHalf()
	if err != nil {
		t.Fatal(err)
	}

	clientHalf, err := c.MaskTLFCryptKey(serverHalf, cryptKey)
	if err != nil {
		t.Fatal(err)
	}

	var nonce [24]byte
	err = cryptoRandRead(nonce[:])
	if err != nil {
		t.Fatal(err)
	}

	keypair, err := libkb.ImportKeypairFromKID(cryptPrivateKey.getPublicKey().kid)
	if err != nil {
		t.Fatal(err)
	}

	dhKeyPair, ok := keypair.(libkb.NaclDHKeyPair)
	if !ok {
		t.Fatal(libkb.KeyCannotEncryptError{})
	}

	encryptedData := box.Seal(nil, clientHalf.data[:], &nonce, (*[32]byte)(&dhKeyPair.Public), (*[32]byte)(&ephPrivateKey.data))
	encryptedClientHalf := EncryptedTLFCryptKeyClientHalf{
		Version:       EncryptionSecretbox,
		Nonce:         nonce[:],
		EncryptedData: encryptedData,
	}

	decryptedClientHalf, err := c.DecryptTLFCryptKeyClientHalf(
		context.Background(), ephPublicKey, encryptedClientHalf)
	if err != nil {
		t.Fatal(err)
	}

	if clientHalf != decryptedClientHalf {
		t.Error("clientHalf != decryptedClientHalf")
	}
}

// Test that decrypting a TLF crypt key client half encrypted with the
// default method (currently nacl/box) works.
func TestCryptoClientDecryptEncryptedTLFCryptKeyClientHalf(t *testing.T) {
	signingKey := MakeFakeSigningKeyOrBust("client sign")
	cryptPrivateKey := MakeFakeCryptPrivateKeyOrBust("client crypt private")
	config := testCryptoClientConfig(t)
	fc := NewFakeCryptoClient(config, signingKey, cryptPrivateKey, nil)
	c := newCryptoClientWithClient(config.Codec(), fc, logger.NewTestLogger(t))

	_, _, ephPublicKey, ephPrivateKey, cryptKey, err := c.MakeRandomTLFKeys()
	if err != nil {
		t.Fatal(err)
	}

	serverHalf, err := c.MakeRandomTLFCryptKeyServerHalf()
	if err != nil {
		t.Fatal(err)
	}

	clientHalf, err := c.MaskTLFCryptKey(serverHalf, cryptKey)
	if err != nil {
		t.Fatal(err)
	}

	// See crypto_common_test.go for tests that this actually
	// performs encryption.
	encryptedClientHalf, err := c.EncryptTLFCryptKeyClientHalf(ephPrivateKey, cryptPrivateKey.getPublicKey(), clientHalf)
	if err != nil {
		t.Fatal(err)
	}

	if encryptedClientHalf.Version != EncryptionSecretbox {
		t.Fatalf("Unexpected encryption version %d", encryptedClientHalf.Version)
	}

	decryptedClientHalf, err := c.DecryptTLFCryptKeyClientHalf(
		context.Background(), ephPublicKey, encryptedClientHalf)
	if err != nil {
		t.Fatal(err)
	}

	if clientHalf != decryptedClientHalf {
		t.Error("clientHalf != decryptedClientHalf")
	}
}

// Test that decrypting a TLF crypt key client half encrypted with the
// default method (currently nacl/box) works.
func TestCryptoClientDecryptEmptyEncryptedTLFCryptKeyClientHalfAny(t *testing.T) {
	signingKey := MakeFakeSigningKeyOrBust("client sign")
	cryptPrivateKey := MakeFakeCryptPrivateKeyOrBust("client crypt private")
	config := testCryptoClientConfig(t)
	fc := NewFakeCryptoClient(config, signingKey, cryptPrivateKey, nil)
	c := newCryptoClientWithClient(config.Codec(), fc, logger.NewTestLogger(t))

	keys := make([]EncryptedTLFCryptKeyClientAndEphemeral, 0, 0)

	_, _, err := c.DecryptTLFCryptKeyClientHalfAny(
		context.Background(), keys)
	if _, ok := err.(NoKeysError); !ok {
		t.Fatal(err)
	}
}

// Test that decrypting a TLF crypt key client half encrypted with the
// default method (currently nacl/box) works.
func TestCryptoClientDecryptEncryptedTLFCryptKeyClientHalfAny(t *testing.T) {
	signingKey := MakeFakeSigningKeyOrBust("client sign")
	cryptPrivateKey := MakeFakeCryptPrivateKeyOrBust("client crypt private")
	config := testCryptoClientConfig(t)
	fc := NewFakeCryptoClient(config, signingKey, cryptPrivateKey, nil)
	c := newCryptoClientWithClient(config.Codec(), fc, logger.NewTestLogger(t))

	keys := make([]EncryptedTLFCryptKeyClientAndEphemeral, 0, 4)
	clientHalves := make([]TLFCryptKeyClientHalf, 0, 4)
	for i := 0; i < 4; i++ {
		_, _, ephPublicKey, ephPrivateKey, cryptKey, err := c.MakeRandomTLFKeys()
		if err != nil {
			t.Fatal(err)
		}

		serverHalf, err := c.MakeRandomTLFCryptKeyServerHalf()
		if err != nil {
			t.Fatal(err)
		}

		clientHalf, err := c.MaskTLFCryptKey(serverHalf, cryptKey)
		if err != nil {
			t.Fatal(err)
		}

		// See crypto_common_test.go for tests that this actually
		// performs encryption.
		encryptedClientHalf, err := c.EncryptTLFCryptKeyClientHalf(ephPrivateKey, cryptPrivateKey.getPublicKey(), clientHalf)
		if err != nil {
			t.Fatal(err)
		}

		if encryptedClientHalf.Version != EncryptionSecretbox {
			t.Fatalf("Unexpected encryption version %d", encryptedClientHalf.Version)
		}
		keys = append(keys, EncryptedTLFCryptKeyClientAndEphemeral{
			PubKey:     cryptPrivateKey.getPublicKey(),
			ClientHalf: encryptedClientHalf,
			EPubKey:    ephPublicKey,
		})
		clientHalves = append(clientHalves, clientHalf)
	}

	decryptedClientHalf, index, err := c.DecryptTLFCryptKeyClientHalfAny(
		context.Background(), keys)
	if err != nil {
		t.Fatal(err)
	}

	if index != 0 {
		t.Errorf("expected first key to work. Actual key index: %d", index)
	}

	if clientHalves[0] != decryptedClientHalf {
		t.Error("clientHalf != decryptedClientHalf")
	}
}

// Test various failure cases for DecryptTLFCryptKeyClientHalf.
func TestCryptoClientDecryptTLFCryptKeyClientHalfFailures(t *testing.T) {
	signingKey := MakeFakeSigningKeyOrBust("client sign")
	cryptPrivateKey := MakeFakeCryptPrivateKeyOrBust("client crypt private")
	config := testCryptoClientConfig(t)
	fc := NewFakeCryptoClient(config, signingKey, cryptPrivateKey, nil)
	c := newCryptoClientWithClient(config.Codec(), fc, logger.NewTestLogger(t))

	_, _, ephPublicKey, ephPrivateKey, cryptKey, err := c.MakeRandomTLFKeys()
	if err != nil {
		t.Fatal(err)
	}

	serverHalf, err := c.MakeRandomTLFCryptKeyServerHalf()
	if err != nil {
		t.Fatal(err)
	}

	clientHalf, err := c.MaskTLFCryptKey(serverHalf, cryptKey)
	if err != nil {
		t.Fatal(err)
	}

	encryptedClientHalf, err := c.EncryptTLFCryptKeyClientHalf(ephPrivateKey, cryptPrivateKey.getPublicKey(), clientHalf)
	if err != nil {
		t.Fatal(err)
	}

	var expectedErr error

	// Wrong version.

	encryptedClientHalfWrongVersion := encryptedClientHalf
	encryptedClientHalfWrongVersion.Version++
	expectedErr = UnknownEncryptionVer{encryptedClientHalfWrongVersion.Version}
	ctx := context.Background()
	_, err = c.DecryptTLFCryptKeyClientHalf(ctx, ephPublicKey,
		encryptedClientHalfWrongVersion)
	if err != expectedErr {
		t.Errorf("Expected %v, got %v", expectedErr, err)
	}

	// Wrong sizes.

	encryptedClientHalfWrongSize := encryptedClientHalf
	encryptedClientHalfWrongSize.EncryptedData = encryptedClientHalfWrongSize.EncryptedData[:len(encryptedClientHalfWrongSize.EncryptedData)-1]
	expectedErr = libkb.DecryptionError{}
	_, err = c.DecryptTLFCryptKeyClientHalf(ctx, ephPublicKey,
		encryptedClientHalfWrongSize)
	if err != expectedErr {
		t.Errorf("Expected %v, got %v", expectedErr, err)
	}

	encryptedClientHalfWrongNonceSize := encryptedClientHalf
	encryptedClientHalfWrongNonceSize.Nonce = encryptedClientHalfWrongNonceSize.Nonce[:len(encryptedClientHalfWrongNonceSize.Nonce)-1]
	expectedErr = InvalidNonceError{encryptedClientHalfWrongNonceSize.Nonce}
	_, err = c.DecryptTLFCryptKeyClientHalf(ctx, ephPublicKey,
		encryptedClientHalfWrongNonceSize)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected %v, got %v", expectedErr, err)
	}

	// Corrupt key.

	ephPublicKeyCorrupt := ephPublicKey
	ephPublicKeyCorrupt.data[0] = ^ephPublicKeyCorrupt.data[0]
	expectedErr = libkb.DecryptionError{}
	_, err = c.DecryptTLFCryptKeyClientHalf(ctx, ephPublicKeyCorrupt,
		encryptedClientHalf)
	if err != expectedErr {
		t.Errorf("Expected %v, got %v", expectedErr, err)
	}

	// Corrupt data.

	encryptedClientHalfCorruptData := encryptedClientHalf
	encryptedClientHalfCorruptData.EncryptedData[0] = ^encryptedClientHalfCorruptData.EncryptedData[0]
	expectedErr = libkb.DecryptionError{}
	_, err = c.DecryptTLFCryptKeyClientHalf(ctx, ephPublicKey,
		encryptedClientHalfCorruptData)
	if err != expectedErr {
		t.Errorf("Expected %v, got %v", expectedErr, err)
	}
}

// Test that canceling a signing RPC returns the correct error
func TestCryptoClientDecryptTLFCryptKeyClientHalfCanceled(t *testing.T) {
	signingKey := MakeFakeSigningKeyOrBust("client sign")
	cryptPrivateKey := MakeFakeCryptPrivateKeyOrBust("client crypt private")
	config := testCryptoClientConfig(t)
	ctlChan := make(chan struct{})
	fc := NewFakeCryptoClient(config, signingKey, cryptPrivateKey, ctlChan)
	c := newCryptoClientWithClient(config.Codec(), cancelableClient{fc}, logger.NewTestLogger(t))

	_, _, ephPublicKey, ephPrivateKey, cryptKey, err := c.MakeRandomTLFKeys()
	if err != nil {
		t.Fatal(err)
	}

	serverHalf, err := c.MakeRandomTLFCryptKeyServerHalf()
	if err != nil {
		t.Fatal(err)
	}

	clientHalf, err := c.MaskTLFCryptKey(serverHalf, cryptKey)
	if err != nil {
		t.Fatal(err)
	}

	encryptedClientHalf, err := c.EncryptTLFCryptKeyClientHalf(ephPrivateKey, cryptPrivateKey.getPublicKey(), clientHalf)
	if err != nil {
		t.Fatal(err)
	}

	f := func(ctx context.Context) error {
		_, err = c.DecryptTLFCryptKeyClientHalf(ctx, ephPublicKey,
			encryptedClientHalf)
		return err
	}
	testWithCanceledContext(t, context.Background(), ctlChan, ctlChan, f)
}
