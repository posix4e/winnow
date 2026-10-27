import Std.Data.HashMap
import Winnow.Keys.Unicode

/-! # Wallet secret storage (port of `Keys/KeyStore.swift`)

`KeyStore` is a structure of functions over a monad, the Lean form of the Swift protocol. The device
implementation (`KeychainStore.swift`, Security framework) is not ported here: it becomes an iOS capability.
`InMemoryKeyStore` is the store of `Tests/Support/InMemoryKeyStore.swift`. -/

namespace Winnow.Keys

inductive KeyStoreError where
  | notFound (walletID : String)
  | alreadyExists (walletID : String)
  | malformedSecret
  /-- An `OSStatus` from the keychain. -/
  | keychain (status : Int32)
  deriving Repr, DecidableEq

def KeyStoreError.name : KeyStoreError → String
  | .notFound _ => "notFound" | .alreadyExists _ => "alreadyExists"
  | .malformedSecret => "malformedSecret" | .keychain _ => "keychain"

def errSecUserCanceled : Int32 := -128
def errSecAuthFailed : Int32 := -25293
def errSecInteractionNotAllowed : Int32 := -25308

/-- `errorDescription`. A keychain status other than the three named ones is described by the Security
framework (`SecCopyErrorMessageString`), which belongs to the keychain capability: `none` here. -/
def KeyStoreError.errorDescription : KeyStoreError → Option String
  | .notFound w => some s!"The protected key for wallet {w} is missing from this device."
  | .alreadyExists w => some s!"This device already contains a protected key for wallet {w}."
  | .malformedSecret => some "The protected wallet key is damaged or has an unsupported format."
  | .keychain s =>
    if s == errSecUserCanceled then some "Unlocking the wallet key was cancelled."
    else if s == errSecAuthFailed then some "The device did not confirm it was you, so the wallet key stays locked."
    else if s == errSecInteractionNotAllowed then
      some "The wallet key can only be unlocked while Winnow is on screen and the device is unlocked."
    else none

/-- The root secret of a wallet, as held by a `KeyStore`. -/
inductive WalletSecret where
  /-- BIP39 mnemonic sentence (single spaces, checksummed). -/
  | mnemonic (words : String)
  /-- BIP32 master extended private key, Base58Check (xprv/tprv). -/
  | masterKey (xprv : String)
  deriving Repr, DecidableEq, Inhabited

namespace WalletSecret

/-- Tagged text encoding: a header line (`mnemonic` / `xprv`) and a payload line. -/
def serialized : WalletSecret → ByteArray
  | .mnemonic w => ("mnemonic\n" ++ w).toUTF8
  | .masterKey x => ("xprv\n" ++ x).toUTF8

/-- `WalletSecret(serialized:)`: lossy UTF-8, then exactly two lines split as Swift `Character`s
(so `"\r\n"` does not end a line). -/
def parse (b : ByteArray) : Except KeyStoreError WalletSecret :=
  match Unicode.splitCharacters (Unicode.decodeUTF8Lossy b) '\n' with
  | [h, payload] =>
    if h == "mnemonic" then pure (.mnemonic payload)
    else if h == "xprv" then pure (.masterKey payload)
    else throw .malformedSecret
  | _ => throw .malformedSecret

end WalletSecret

/-- Secret storage for wallets, keyed by wallet ID; secrets stay on the device. -/
structure KeyStore (m : Type → Type) [Monad m] where
  /-- Stores `secret` under `walletID`; `alreadyExists` if occupied. -/
  store : WalletSecret → String → ExceptT KeyStoreError m Unit
  /-- Loads the secret for `walletID`; `notFound` if absent. -/
  load : String → ExceptT KeyStoreError m WalletSecret
  /-- Deletes the secret for `walletID`; deleting an absent ID is a no-op. -/
  delete : String → ExceptT KeyStoreError m Unit
  /-- Brings a secret stored by an earlier version up to the store's current protection; whether
  anything changed. Stores with one notion of protection have nothing to do. -/
  upgradeProtection : String → ExceptT KeyStoreError m Bool := fun _ => pure false

/-- The contents of an in-memory store. Swift dictionary keys compare by canonical equivalence, so IDs
are kept in NFD. -/
abbrev InMemorySecrets := Std.HashMap String WalletSecret

/-- An in-memory `KeyStore` over a state of secrets (not persisted). -/
def InMemoryKeyStore {m : Type → Type} [Monad m] [MonadStateOf InMemorySecrets m] : KeyStore m where
  store secret id := do
    let k := Unicode.nfd id
    if (← (get : m InMemorySecrets)).contains k then throw (.alreadyExists id)
    modify (m := m) (σ := InMemorySecrets) (·.insert k secret)
  load id := do
    match (← (get : m InMemorySecrets))[Unicode.nfd id]? with
    | some s => pure s
    | none => throw (.notFound id)
  delete id := modify (m := m) (σ := InMemorySecrets) (·.erase (Unicode.nfd id))

end Winnow.Keys
