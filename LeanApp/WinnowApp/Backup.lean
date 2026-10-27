import WinnowApp.Common

/-! BackupSection.swift (the backup file and the recovery words, on beginner mode's Back up page and in
Settings), ExportBundleView and RevealPhraseView. Both results are sensitive: each request carries a
fresh epoch, and an answer counts only while that epoch is current and the app is active. -/

namespace WinnowApp
open ElmLean

/-- Start a sensitive operation: a new epoch, so an older answer can never land. -/
def Model.beginEpoch (m : Model) : Model := { m with epoch := m.epoch + 1 }

def Model.export (m : Model) : Model × List Cmd :=
  let m := m.beginEpoch
  let name := s!"winnow-{m.settings.network.name}-{m.walletID.getD "wallet"}.json"
  ({ m with exportState := { m.exportState with busy := true, error := none, file := none }, confirm := none },
   m.discardExport ++ [.exportBundle m.generation m.epoch m.exportState.includeMnemonic name])

def stepBackup (msg : BackupMsg) (m : Model) : Model × List Cmd :=
  match msg with
  | .openExport => (({ m with exportState := {} }.beginEpoch).present .exportBundle, [])
  | .setIncludeMnemonic b =>
    -- any change resets the export (`resetExport`): the old file must not be shared as the new one
    ({ m.beginEpoch with exportState := { includeMnemonic := b } }, m.discardExport)
  | .createExport =>
    if m.exportState.busy then (m, []) else
    if m.exportState.includeMnemonic then ({ m with confirm := some .exportWithPhrase }, []) else m.export
  | .confirmExport => m.export
  | .reveal =>
    if m.reveal.revealing || m.walletID.isNone then (m, []) else
    let m := m.beginEpoch
    ({ m with reveal := { revealing := true } }, [.revealPhrase m.generation m.epoch])
  | .copyPhrase =>
    ({ m with reveal := { m.reveal with copied := true } }, [.copy (" ".intercalate m.reveal.words) .recoveryPhrase])

/-! ## View -/

def backupSection (m : Model) : H :=
  .section "Backup" "Keep both your recovery words and a backup file. The file restores your history and shared accounts; the words restore your signing key."
    ([ .button "Back up wallet" .plain (if m.walletID.isNone then none else some (.backup .openExport))
     , .button "Show recovery phrase" .plain (if m.walletID.isNone || m.reveal.revealing then none else some (.backup .reveal)) ] ++
     (if m.hasSheet .revealPhrase then [] else errorRows m.reveal.error))

/-- Beginner mode's Back up page. -/
def backupScreen (m : Model) (overlays : List H) : H :=
  .screen "Back up" (some (.home .pop)) ([.list [backupSection m]] ++ overlays)

def exportSheet (m : Model) (inner : List H) : H :=
  let e := m.exportState
  .sheet "Back up wallet" (some .closeSheet)
    ([ closeRow "Close"
     , .section "" "The file saves your history and shared accounts. Each signer needs their own key backup."
         ([.toggle "Include recovery phrase" e.includeMnemonic (fun b => .backup (.setIncludeMnemonic b))] ++
          (if e.includeMnemonic then [body "This file includes your phone’s signing key. Keep it as private as your recovery words."] else [])) ] ++
     (match e.error with | some err => [.section "" "" (errorRows (some err))] | none => []) ++
     (match e.file with
      | some file =>
        [.section "Backup ready" ""
          [ body (if e.includeMnemonic then "Includes your recovery words. Keep this file private."
                  else "Recovery words are not included. Keep them separately.")
          , .share "Save or share backup" file (file := true) ]]
      | none => [.section "" "" [.button "Create backup file" .primary (if e.busy then none else some (.backup .createExport))]]) ++
     inner)

/-- Two words per row, numbered, like the reveal grid. -/
def wordGrid (words : List String) (captured : Bool := false) : H :=
  if captured then
    .row [.icon "record.circle", body "Hidden while the screen is being recorded or mirrored."] else
  let numbered := words.zipIdx.map fun (w, i) => s!"{i + 1}. {w}"
  let rec pairs : List String → List H
    | a :: b :: rest => .row [body a, .spacer, body b] :: pairs rest
    | [a] => [.row [body a]]
    | [] => []
  .col (pairs numbered)

def revealSheet (m : Model) (inner : List H) : H :=
  .sheet "Recovery phrase" (some .closeSheet)
    ([ closeRow "Close"
     , .section "" "These words restore this phone's signing key. Keep them private, and save a backup file for your history and shared accounts."
         [wordGrid m.reveal.words m.captured]
     , .section "" "Copying is less private than paper. The clipboard item stays on this device and expires after two minutes."
         [.button (if m.reveal.copied then "Copied for 2 minutes" else "Copy recovery phrase") .plain (some (.backup .copyPhrase))] ] ++
     inner)

end WinnowApp
