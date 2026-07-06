"""Receive tab — open a PGP file, decrypt + verify, save the original (req. 5).

On open we first inspect the file (no passphrase needed) to show what services
were applied, then process it: decrypt (asking the passphrase only if the message
is encrypted to one of our keys), decompress, and verify the signature. The
outcome — including the signer's identity — is shown clearly; failures produce a
plain error instead of a result.
"""

from tkinter import filedialog

import customtkinter as ctk

from pgp.pgpReceive import pgpReceive
from pgp.fileSerializer import inspectMessage
from pgp.errors import PGPError, WrongPassphrase, NeedPassphrase, MessageError
from . import dialogs as dlg


class ReceiveView(ctk.CTkScrollableFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.km = app.km
        self.result = None             # last successful MessageResult (for saving)
        self._build()

    def _build(self):
        ctk.CTkButton(self, text="Open message file…", height=40,
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=self._open).pack(fill="x", pady=(6, 8))
        self.file_label = ctk.CTkLabel(self, text="No file opened.", anchor="w",
                                       text_color="#9aa3b2", font=ctk.CTkFont(size=12))
        self.file_label.pack(fill="x")

        # detected services
        self.detected = ctk.CTkLabel(self, text="", anchor="w",
                                     font=ctk.CTkFont(size=13))
        self.detected.pack(fill="x", pady=(10, 2))

        # verification outcome card
        self.outcome = ctk.CTkLabel(self, text="", anchor="w", justify="left",
                                    font=ctk.CTkFont(size=13), wraplength=820)
        self.outcome.pack(fill="x", pady=(2, 8))

        ctk.CTkLabel(self, text="Original message", anchor="w",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(fill="x", pady=(10, 4))
        self.textbox = ctk.CTkTextbox(self, height=220, font=ctk.CTkFont(size=13))
        self.textbox.pack(fill="x")
        self.textbox.configure(state="disabled")

        self.save_btn = ctk.CTkButton(self, text="Save message…", height=36,
                                      fg_color="#2b2f3a", hover_color="#363b48",
                                      command=self._save, state="disabled")
        self.save_btn.pack(fill="x", pady=(8, 6))

    # ------------------------------------------------------------------ #
    def _open(self):
        path = filedialog.askopenfilename(
            title="Open PGP message", filetypes=[("PGP message", "*.pgp"), ("All files", "*.*")])
        if not path:
            return
        self.file_label.configure(text=path)
        with open(path, "rb") as f:
            raw = f.read()

        # 1) inspect (no secrets needed)
        try:
            info = inspectMessage(raw)
        except MessageError as exc:
            self._fail(str(exc)); return

        badges = []
        if info.encrypted:  badges.append(f"Encrypted ({info.sym_algo})")
        if info.signed:     badges.append("Signed")
        if info.compressed: badges.append("Compressed")
        if info.radix64:    badges.append("Radix-64")
        self.detected.configure(
            text="Detected:  " + ("  ·  ".join(badges) if badges else "plain (no services)"),
            text_color="#9aa3b2")

        # 2) process, prompting for a passphrase only if needed
        passphrase = None
        while True:
            try:
                result = pgpReceive(self.km, raw, passphrase=passphrase)
                break
            except NeedPassphrase as need:
                res = dlg.PassphraseDialog(
                    self.app,
                    f"This message is encrypted to your key:\n{need.user_id or need.key_id}\n"
                    "Enter its passphrase to decrypt.").show()
                if not res:
                    self._reset_outcome("Decryption cancelled."); return
                passphrase = res["passphrase"]
            except WrongPassphrase:
                if not dlg.ask_yes_no(self.app, "Wrong passphrase",
                                      "That passphrase did not work. Try again?"):
                    self._reset_outcome("Decryption cancelled."); return
                passphrase = None
            except PGPError as exc:
                self._fail(str(exc)); return

        self._show_result(result)

    # ------------------------------------------------------------------ #
    def _show_result(self, result):
        self.result = result
        lines = []
        if result.was_encrypted:
            lines.append(f"🔓  Decrypted with {result.sym_algo} (session key unwrapped by your private key).")
        if result.was_compressed:
            lines.append("🗜  Decompressed (ZIP).")

        if not result.was_signed:
            lines.append("✍  Not signed — authenticity cannot be checked.")
        elif result.signature_valid is True:
            lines.append(f"✅  Signature VALID — signed by {result.signer_user_id} "
                         f"at {result.sig_timestamp}.")
        elif result.signature_valid is False:
            lines.append("❌  Signature INVALID — the message may have been altered "
                         "or was not signed by the claimed key.")
        else:
            lines.append(f"⚠  {result.signer_note}")

        color = "#34d399"
        if result.signature_valid is False:
            color = "#f87171"
        elif result.signature_valid is None and result.was_signed:
            color = "#fbbf24"
        self.outcome.configure(text="\n".join(lines), text_color=color)

        # show the message text (decode for display; keep raw bytes for saving)
        try:
            shown = result.message_bytes.decode("utf-8")
        except UnicodeDecodeError:
            shown = f"[binary data — {len(result.message_bytes)} bytes — use “Save message…”]"
        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", "end")
        self.textbox.insert("1.0", shown)
        self.textbox.configure(state="disabled")
        self.save_btn.configure(state="normal")

    def _save(self):
        if not self.result:
            return
        path = filedialog.asksaveasfilename(
            title="Save original message", initialfile=self.result.filename)
        if not path:
            return
        with open(path, "wb") as f:
            f.write(self.result.message_bytes)
        dlg.show_message(self.app, "Saved", f"Original message saved to:\n{path}", "success")

    # ------------------------------------------------------------------ #
    def _reset_outcome(self, note):
        self.outcome.configure(text=note, text_color="#9aa3b2")

    def _fail(self, msg):
        self.result = None
        self.detected.configure(text="")
        self.outcome.configure(text=f"❌  {msg}", text_color="#f87171")
        self.textbox.configure(state="normal"); self.textbox.delete("1.0", "end")
        self.textbox.configure(state="disabled")
        self.save_btn.configure(state="disabled")
        dlg.show_message(self.app, "Could not read message", msg, "error")
