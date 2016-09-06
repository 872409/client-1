// Auto-generated by avdl-compiler v1.3.5 (https://github.com/keybase/node-avdl-compiler)
//   Input file: avdl/keybase1/account.avdl

package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type PassphraseChangeArg struct {
	SessionID     int    `codec:"sessionID" json:"sessionID"`
	OldPassphrase string `codec:"oldPassphrase" json:"oldPassphrase"`
	Passphrase    string `codec:"passphrase" json:"passphrase"`
	Force         bool   `codec:"force" json:"force"`
}

type PassphrasePromptArg struct {
	SessionID int         `codec:"sessionID" json:"sessionID"`
	GuiArg    GUIEntryArg `codec:"guiArg" json:"guiArg"`
}

type AccountInterface interface {
	// Change the passphrase from old to new. If old isn't set, and force is false,
	// then prompt at the UI for it. If old isn't set and force is true, then we'll
	// try to force a passphrase change.
	PassphraseChange(context.Context, PassphraseChangeArg) error
	PassphrasePrompt(context.Context, PassphrasePromptArg) (GetPassphraseRes, error)
}

func AccountProtocol(i AccountInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.account",
		Methods: map[string]rpc.ServeHandlerDescription{
			"passphraseChange": {
				MakeArg: func() interface{} {
					ret := make([]PassphraseChangeArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PassphraseChangeArg)
					if !ok {
						err = rpc.NewTypeError((*[]PassphraseChangeArg)(nil), args)
						return
					}
					err = i.PassphraseChange(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"passphrasePrompt": {
				MakeArg: func() interface{} {
					ret := make([]PassphrasePromptArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PassphrasePromptArg)
					if !ok {
						err = rpc.NewTypeError((*[]PassphrasePromptArg)(nil), args)
						return
					}
					ret, err = i.PassphrasePrompt(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type AccountClient struct {
	Cli rpc.GenericClient
}

// Change the passphrase from old to new. If old isn't set, and force is false,
// then prompt at the UI for it. If old isn't set and force is true, then we'll
// try to force a passphrase change.
func (c AccountClient) PassphraseChange(ctx context.Context, __arg PassphraseChangeArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.account.passphraseChange", []interface{}{__arg}, nil)
	return
}

func (c AccountClient) PassphrasePrompt(ctx context.Context, __arg PassphrasePromptArg) (res GetPassphraseRes, err error) {
	err = c.Cli.Call(ctx, "keybase.1.account.passphrasePrompt", []interface{}{__arg}, &res)
	return
}
