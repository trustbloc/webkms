/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -self_package mocks -package rest_test . Cmd

package rest_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/controller/command"
	. "github.com/trustbloc/kms/pkg/controller/rest"
)

func TestOperation_CreateDID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := NewMockCmd(gomock.NewController(t))

		cmd.EXPECT().CreateDID(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
			require.NoError(t, unwrapRequest(r, nil))
		}).Return(nil).Times(1)

		op := New(cmd)

		require.Equal(t, http.StatusOK, handleRequest(t, op, DIDPath, http.MethodPost, bytes.NewReader(nil)))
	})

	t.Run("Fail to read request body", func(t *testing.T) {
		cmd := NewMockCmd(gomock.NewController(t))

		op := New(cmd)

		require.Equal(t, http.StatusInternalServerError,
			handleRequest(t, op, DIDPath, http.MethodPost, &failingReader{}))
	})

	t.Run("Fail to execute command", func(t *testing.T) {
		cmd := NewMockCmd(gomock.NewController(t))

		cmd.EXPECT().CreateDID(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {}).
			Return(errors.New("command error"))

		op := New(cmd)

		require.Equal(t, http.StatusInternalServerError,
			handleRequest(t, op, DIDPath, http.MethodPost, bytes.NewReader(nil)))
	})
}

func TestOperation_CreateKeyStore(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().CreateKeyStore(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.CreateKeyStoreRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, "did:example:test", req.Controller)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := `{
		"controller": "did:example:test"
	}`

	require.Equal(t, http.StatusOK, handleRequest(t, op, KeyStorePath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_CreateKey(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().CreateKey(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.CreateKeyRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, kms.ED25519Type, req.KeyType)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := `{
		"key_type": "ED25519"
	}`

	require.Equal(t, http.StatusOK, handleRequest(t, op, KeyPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_ImportKey(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().ImportKey(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.ImportKeyRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, kms.ED25519Type, req.KeyType)
		require.Equal(t, []byte("key material"), req.Key)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"key": "%s",
		"key_type": "ED25519"
	}`, base64.StdEncoding.EncodeToString([]byte("key material")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, KeyPath, http.MethodPut, bytes.NewBufferString(body)))
}

func TestOperation_ExportKey(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().ExportKey(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		require.NoError(t, unwrapRequest(r, nil))
	}).Return(nil).Times(1)

	op := New(cmd)

	require.Equal(t, http.StatusOK, handleRequest(t, op, ExportKeyPath, http.MethodGet, bytes.NewReader(nil)))
}

func TestOperation_Sign(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().Sign(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.SignRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("test message"), req.Message)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"message": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("test message")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, SignPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_Verify(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().Verify(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.VerifyRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("signature"), req.Signature)
		require.Equal(t, []byte("test message"), req.Message)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"signature": "%s",
		"message": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("signature")),
		base64.StdEncoding.EncodeToString([]byte("test message")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, VerifyPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_Encrypt(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.EncryptRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("test message"), req.Message)
		require.Equal(t, []byte("associated data"), req.AssociatedData)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"message": "%s",
		"associated_data": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("test message")),
		base64.StdEncoding.EncodeToString([]byte("associated data")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, EncryptPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_Decrypt(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().Decrypt(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.DecryptRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("ciphertext"), req.Ciphertext)
		require.Equal(t, []byte("associated data"), req.AssociatedData)
		require.Equal(t, []byte("nonce"), req.Nonce)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"ciphertext": "%s",
		"associated_data": "%s",
		"nonce": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		base64.StdEncoding.EncodeToString([]byte("associated data")),
		base64.StdEncoding.EncodeToString([]byte("nonce")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, DecryptPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_ComputeMAC(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().ComputeMAC(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.ComputeMACRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("data"), req.Data)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"data": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("data")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, ComputeMACPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_VerifyMAC(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().VerifyMAC(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.VerifyMACRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("mac"), req.MAC)
		require.Equal(t, []byte("data"), req.Data)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"mac": "%s",
		"data": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("mac")),
		base64.StdEncoding.EncodeToString([]byte("data")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, VerifyMACPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_SignMulti(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().SignMulti(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.SignMultiRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, [][]byte{[]byte("test message 1"), []byte("test message 2")}, req.Messages)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"messages": ["%s", "%s"]
	}`, base64.StdEncoding.EncodeToString([]byte("test message 1")),
		base64.StdEncoding.EncodeToString([]byte("test message 2")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, SignMultiPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_VerifyMulti(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().VerifyMulti(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.VerifyMultiRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("signature"), req.Signature)
		require.Equal(t, [][]byte{[]byte("test message 1"), []byte("test message 2")}, req.Messages)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"signature": "%s",
		"messages": ["%s", "%s"]
	}`, base64.StdEncoding.EncodeToString([]byte("signature")),
		base64.StdEncoding.EncodeToString([]byte("test message 1")),
		base64.StdEncoding.EncodeToString([]byte("test message 2")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, VerifyMultiPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_DeriveProof(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().DeriveProof(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.DeriveProofRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, [][]byte{[]byte("test message 1"), []byte("test message 2")}, req.Messages)
		require.Equal(t, []byte("signature"), req.Signature)
		require.Equal(t, []byte("nonce"), req.Nonce)
		require.Equal(t, []int{1, 2}, req.RevealedIndexes)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"messages": ["%s", "%s"],
		"signature": "%s",
		"nonce": "%s",
		"revealed_indexes": [1, 2]
	}`, base64.StdEncoding.EncodeToString([]byte("test message 1")),
		base64.StdEncoding.EncodeToString([]byte("test message 2")),
		base64.StdEncoding.EncodeToString([]byte("signature")),
		base64.StdEncoding.EncodeToString([]byte("nonce")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, DeriveProofPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_VerifyProof(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().VerifyProof(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.VerifyProofRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("proof"), req.Proof)
		require.Equal(t, [][]byte{[]byte("test message 1"), []byte("test message 2")}, req.Messages)
		require.Equal(t, []byte("nonce"), req.Nonce)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"proof": "%s",
		"messages": ["%s", "%s"],
		"nonce": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("proof")),
		base64.StdEncoding.EncodeToString([]byte("test message 1")),
		base64.StdEncoding.EncodeToString([]byte("test message 2")),
		base64.StdEncoding.EncodeToString([]byte("nonce")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, VerifyProofPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_Easy(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().WrapKey(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.EasyRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("payload"), req.Payload)
		require.Equal(t, []byte("nonce"), req.Nonce)
		require.Equal(t, []byte("public key material"), req.TheirPub)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"payload": "%s",
		"nonce": "%s",
		"their_pub": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("payload")),
		base64.StdEncoding.EncodeToString([]byte("nonce")),
		base64.StdEncoding.EncodeToString([]byte("public key material")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, WrapKeyPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_EasyOpen(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().UnwrapKey(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.EasyOpenRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("ciphertext"), req.Ciphertext)
		require.Equal(t, []byte("nonce"), req.Nonce)
		require.Equal(t, []byte("public key material"), req.TheirPub)
		require.Equal(t, []byte("public key material"), req.MyPub)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"ciphertext": "%s",
		"nonce": "%s",
		"their_pub": "%s",
		"my_pub": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		base64.StdEncoding.EncodeToString([]byte("nonce")),
		base64.StdEncoding.EncodeToString([]byte("public key material")),
		base64.StdEncoding.EncodeToString([]byte("public key material")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, UnwrapKeyPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_SealOpen(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().UnwrapKey(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.SealOpenRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("ciphertext"), req.Ciphertext)
		require.Equal(t, []byte("public key material"), req.MyPub)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"ciphertext": "%s",
		"my_pub": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		base64.StdEncoding.EncodeToString([]byte("public key material")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, UnwrapKeyPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_WrapKey(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().WrapKey(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.WrapKeyRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("cek"), req.CEK)
		require.Equal(t, []byte("apu"), req.APU)
		require.Equal(t, []byte("apv"), req.APV)

		require.NotNil(t, req.RecipientPubKey)
		require.Equal(t, "key id", req.RecipientPubKey.KID)
		require.Equal(t, []byte("x"), req.RecipientPubKey.X)
		require.Equal(t, []byte("y"), req.RecipientPubKey.Y)
		require.Equal(t, "curve", req.RecipientPubKey.Curve)
		require.Equal(t, "type", req.RecipientPubKey.Type)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"cek": "%s",
		"apu": "%s",
		"apv": "%s",
		"recipient_pub_key": {
			"kid": "key id",
			"x": "%s",
			"y": "%s",
			"curve": "curve",
			"type": "type"
		}
	}`, base64.StdEncoding.EncodeToString([]byte("cek")),
		base64.StdEncoding.EncodeToString([]byte("apu")),
		base64.StdEncoding.EncodeToString([]byte("apv")),
		base64.StdEncoding.EncodeToString([]byte("x")),
		base64.StdEncoding.EncodeToString([]byte("y")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, WrapKeyPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_WrapKeyAE(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().WrapKey(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.WrapKeyRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.Equal(t, []byte("cek"), req.CEK)
		require.Equal(t, []byte("apu"), req.APU)
		require.Equal(t, []byte("apv"), req.APV)
		require.Equal(t, []byte("tag"), req.Tag)

		require.NotNil(t, req.RecipientPubKey)
		require.Equal(t, "key id", req.RecipientPubKey.KID)
		require.Equal(t, []byte("x"), req.RecipientPubKey.X)
		require.Equal(t, []byte("y"), req.RecipientPubKey.Y)
		require.Equal(t, "curve", req.RecipientPubKey.Curve)
		require.Equal(t, "type", req.RecipientPubKey.Type)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"cek": "%s",
		"apu": "%s",
		"apv": "%s",
		"recipient_pub_key": {
			"kid": "key id",
			"x": "%s",
			"y": "%s",
			"curve": "curve",
			"type": "type"
		},
		"tag": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("cek")),
		base64.StdEncoding.EncodeToString([]byte("apu")),
		base64.StdEncoding.EncodeToString([]byte("apv")),
		base64.StdEncoding.EncodeToString([]byte("x")),
		base64.StdEncoding.EncodeToString([]byte("y")),
		base64.StdEncoding.EncodeToString([]byte("tag")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, WrapKeyAEPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_UnwrapKey(t *testing.T) {
	cmd := NewMockCmd(gomock.NewController(t))

	cmd.EXPECT().UnwrapKey(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
		var req command.UnwrapKeyRequest
		require.NoError(t, unwrapRequest(r, &req))

		require.NotNil(t, req.WrappedKey)
		require.Equal(t, "key id", req.WrappedKey.KID)
		require.Equal(t, []byte("encrypted cek"), req.WrappedKey.EncryptedCEK)
		require.Equal(t, "alg", req.WrappedKey.Alg)
		require.Equal(t, []byte("apu"), req.WrappedKey.APU)
		require.Equal(t, []byte("apv"), req.WrappedKey.APV)

		require.NotNil(t, req.WrappedKey.EPK)
		require.Equal(t, "key id", req.WrappedKey.EPK.KID)
		require.Equal(t, []byte("x"), req.WrappedKey.EPK.X)
		require.Equal(t, []byte("y"), req.WrappedKey.EPK.Y)
		require.Equal(t, "curve", req.WrappedKey.EPK.Curve)
		require.Equal(t, "type", req.WrappedKey.EPK.Type)

		require.NotNil(t, req.SenderPubKey)
		require.Equal(t, "key id", req.SenderPubKey.KID)
		require.Equal(t, []byte("x"), req.SenderPubKey.X)
		require.Equal(t, []byte("y"), req.SenderPubKey.Y)
		require.Equal(t, "curve", req.SenderPubKey.Curve)
		require.Equal(t, "type", req.SenderPubKey.Type)

		require.Equal(t, []byte("tag"), req.Tag)
	}).Return(nil).Times(1)

	op := New(cmd)

	body := fmt.Sprintf(`{
		"wrapped_key": {
			"kid": "key id",
			"encryptedcek": "%s",
			"epk": {
				"kid": "key id",
				"x": "%s",
				"y": "%s",
				"curve": "curve",
				"type": "type"
			},
			"alg": "alg",
			"apu": "%s",
			"apv": "%s"
		},
		"sender_pub_key": {
			"kid": "key id",
			"x": "%s",
			"y": "%s",
			"curve": "curve",
			"type": "type"
		},
		"tag": "%s"
	}`, base64.StdEncoding.EncodeToString([]byte("encrypted cek")),
		base64.StdEncoding.EncodeToString([]byte("x")),
		base64.StdEncoding.EncodeToString([]byte("y")),
		base64.StdEncoding.EncodeToString([]byte("apu")),
		base64.StdEncoding.EncodeToString([]byte("apv")),
		base64.StdEncoding.EncodeToString([]byte("x")),
		base64.StdEncoding.EncodeToString([]byte("y")),
		base64.StdEncoding.EncodeToString([]byte("tag")))

	require.Equal(t, http.StatusOK, handleRequest(t, op, UnwrapKeyPath, http.MethodPost, bytes.NewBufferString(body)))
}

func TestOperation_HealthCheck(t *testing.T) {
	op := New(nil)

	require.Equal(t, http.StatusOK, handleRequest(t, op, HealthCheckPath, http.MethodGet, bytes.NewBuffer(nil)))
}

func unwrapRequest(r io.Reader, req interface{}) error {
	var wr command.WrappedRequest

	if err := json.NewDecoder(r).Decode(&wr); err != nil {
		return err
	}

	if req != nil {
		return json.Unmarshal(wr.Request, req)
	}

	return nil
}

func handleRequest(t *testing.T, op *Operation, path, method string, body io.Reader) int {
	t.Helper()

	handler := handlerLookup(t, op, path, method)

	req, err := http.NewRequestWithContext(context.Background(), handler.Method(), handler.Path(), body)
	require.NoError(t, err)

	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handler()).Methods(handler.Method())

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	return rr.Code
}

func handlerLookup(t *testing.T, op *Operation, path, method string) Handler {
	t.Helper()

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == path && h.Method() == method {
			return h
		}
	}

	require.Fail(t, "no matching handler found")

	return nil
}

type failingReader struct{}

func (*failingReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read error")
}
