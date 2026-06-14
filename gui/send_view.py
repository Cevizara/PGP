"""Send tab — compose a message and produce a PGP file (requirement 4).

The user types (or loads) a message, ticks any of Sign / Encrypt / Compress /
Radix-64, picks the keys/algorithm, and gets one self-contained file.
"""

import os
from tkinter import filedialog

import customtkinter as ctk

from pgp import message as M
from pgp import ciphers
from pgp.errors import PGPError, WrongPassphrase
from . import dialogs as dlg

NO_KEYS = "— no keys available —"


class SendView(ctk.CTkScrollableFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.km = app.km
        self.loaded_bytes = None       # set when a file is loaded as the source
        self.loaded_filename = None
        self._signer_ids = {}          # label -> key_id
        self._recipient_ids = {}
        self._build()
        self.refresh()

    # ------------------------------------------------------------------ #
    def _section(self, text):
        ctk.CTkLabel(self, text=text, anchor="w",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(fill="x", pady=(14, 4))

    def _build(self):
        self._section("Message")
        self.textbox = ctk.CTkTextbox(self, height=150, font=ctk.CTkFont(size=13))
        self.textbox.pack(fill="x")

        srcbar = ctk.CTkFrame(self, fg_color="transparent")
        srcbar.pack(fill="x", pady=(6, 0))
        ctk.CTkButton(srcbar, text="Load from file…", width=130, height=30,
                      fg_color="#2b2f3a", hover_color="#363b48",
                      command=self._load_file).pack(side="left")
        self.src_label = ctk.CTkLabel(srcbar, text="Source: typed text",
                                      text_color="#9aa3b2", font=ctk.CTkFont(size=12))
        self.src_label.pack(side="left", padx=12)
        self.clear_src_btn = ctk.CTkButton(srcbar, text="Use typed text", width=120, height=30,
                                           fg_color="#2b2f3a", hover_color="#363b48",
                                           command=self._clear_file)
        # shown only when a file is loaded

        # --- options ---------------------------------------------------- #
        self._section("Protection options")

        self.sign_var = ctk.BooleanVar(value=False)
        self.enc_var = ctk.BooleanVar(value=False)
        self.comp_var = ctk.BooleanVar(value=False)
        self.r64_var = ctk.BooleanVar(value=False)

        # Sign row
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", pady=4)
        ctk.CTkCheckBox(row, text="Sign  (authenticity)", variable=self.sign_var,
                        command=self._sync, width=200).pack(side="left")
        ctk.CTkLabel(row, text="with my key:", text_color="#9aa3b2").pack(side="left", padx=(10, 6))
        self.signer_menu = ctk.CTkOptionMenu(row, values=[NO_KEYS], width=300)
        self.signer_menu.pack(side="left")

        # Encrypt row
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", pady=4)
        ctk.CTkCheckBox(row, text="Encrypt  (secrecy)", variable=self.enc_var,
                        command=self._sync, width=200).pack(side="left")
        ctk.CTkLabel(row, text="for:", text_color="#9aa3b2").pack(side="left", padx=(10, 6))
        self.recipient_menu = ctk.CTkOptionMenu(row, values=[NO_KEYS], width=300)
        self.recipient_menu.pack(side="left")

        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(row, text="algorithm:", text_color="#9aa3b2").pack(side="left", padx=(210, 6))
        self.algo_menu = ctk.CTkSegmentedButton(row, values=ciphers.ALGORITHM_NAMES)
        self.algo_menu.set(ciphers.ALGORITHM_NAMES[0])
        self.algo_menu.pack(side="left")

        # Compress + Radix64
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", pady=4)
        ctk.CTkCheckBox(row, text="Compress  (ZIP)", variable=self.comp_var, width=200).pack(side="left")
        ctk.CTkCheckBox(row, text="Radix-64  (ASCII armor)", variable=self.r64_var).pack(side="left", padx=10)

        # --- action ----------------------------------------------------- #
        ctk.CTkButton(self, text="Create message file", height=40,
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=self._create).pack(fill="x", pady=(18, 6))
        self.status = ctk.CTkLabel(self, text="", text_color="#9aa3b2",
                                   anchor="w", font=ctk.CTkFont(size=12))
        self.status.pack(fill="x")

    # ------------------------------------------------------------------ #
    def refresh(self):
        """Rebuild the key dropdowns from the current rings."""
        self._signer_ids = {f"{e.user_id}  ·  {e.key_id}": e.key_id
                            for e in self.km.private_ring}
        # recipients = contacts + own public parts
        recips = {}
        for e in self.km.public_ring:
            recips[f"{e.user_id}  ·  {e.key_id}"] = e.key_id
        for e in self.km.private_ring:
            recips[f"{e.user_id}  ·  {e.key_id}  (me)"] = e.key_id
        self._recipient_ids = recips

        signers = list(self._signer_ids) or [NO_KEYS]
        recipients = list(self._recipient_ids) or [NO_KEYS]
        self.signer_menu.configure(values=signers); self.signer_menu.set(signers[0])
        self.recipient_menu.configure(values=recipients); self.recipient_menu.set(recipients[0])
        self._sync()

    def _sync(self):
        """Enable/disable dropdowns based on the checkboxes."""
        self.signer_menu.configure(state="normal" if self.sign_var.get() else "disabled")
        on = "normal" if self.enc_var.get() else "disabled"
        self.recipient_menu.configure(state=on)
        self.algo_menu.configure(state=on)

    # ------------------------------------------------------------------ #
    def _load_file(self):
        path = filedialog.askopenfilename(title="Choose a file to send")
        if not path:
            return
        with open(path, "rb") as f:
            self.loaded_bytes = f.read()
        self.loaded_filename = os.path.basename(path)
        self.src_label.configure(
            text=f"Source: {self.loaded_filename}  ({len(self.loaded_bytes)} bytes)")
        self.clear_src_btn.pack(side="left")
        self.textbox.configure(state="disabled")

    def _clear_file(self):
        self.loaded_bytes = None
        self.loaded_filename = None
        self.src_label.configure(text="Source: typed text")
        self.clear_src_btn.pack_forget()
        self.textbox.configure(state="normal")

    def _message_source(self):
        if self.loaded_bytes is not None:
            return self.loaded_bytes, self.loaded_filename
        text = self.textbox.get("1.0", "end-1c")
        return text.encode("utf-8"), "message.txt"

    # ------------------------------------------------------------------ #
    def _create(self):
        sign, enc = self.sign_var.get(), self.enc_var.get()
        comp, r64 = self.comp_var.get(), self.r64_var.get()

        data, filename = self._message_source()
        if not data:
            dlg.show_message(self.app, "Empty message",
                             "Type a message or load a file first.", "warn"); return

        signer_key_id = recipient_key_id = None
        signer_passphrase = None

        if sign:
            signer_key_id = self._signer_ids.get(self.signer_menu.get())
            if not signer_key_id:
                dlg.show_message(self.app, "No signing key",
                                 "Generate a key pair first to sign.", "warn"); return
        if enc:
            recipient_key_id = self._recipient_ids.get(self.recipient_menu.get())
            if not recipient_key_id:
                dlg.show_message(self.app, "No recipient key",
                                 "Import a contact's public key first to encrypt.", "warn"); return

        # signing touches the private key -> ask the passphrase
        if sign:
            entry = self.km.private_ring.get(signer_key_id)
            res = dlg.PassphraseDialog(
                self.app, f"Enter the passphrase for your key:\n{entry.user_id}").show()
            if not res:
                return
            signer_passphrase = res["passphrase"]
            if not self.km.verify_passphrase(signer_key_id, signer_passphrase):
                dlg.show_message(self.app, "Wrong passphrase",
                                 "That passphrase does not unlock the signing key.", "error"); return

        try:
            blob = M.pgpSend(
                self.km, data, filename,
                signRequired=sign, signerKeyId=signer_key_id, passphrase=signer_passphrase,
                confidentialityRequired=enc, recipientKeyId=recipient_key_id,
                symAlgo=self.algo_menu.get(), compressRequired=comp, radix64Required=r64)
        except WrongPassphrase:
            dlg.show_message(self.app, "Wrong passphrase", "Could not unlock the signing key.", "error"); return
        except PGPError as exc:
            dlg.show_message(self.app, "Could not create message", str(exc), "error"); return

        default_name = (filename.rsplit(".", 1)[0] if "." in filename else filename) + ".pgp"
        path = filedialog.asksaveasfilename(
            title="Save PGP message", defaultextension=".pgp", initialfile=default_name,
            filetypes=[("PGP message", "*.pgp"), ("All files", "*.*")])
        if not path:
            return
        with open(path, "wb") as f:
            f.write(blob)

        applied = ", ".join(n for n, on in
                            [("sign", sign), ("encrypt", enc), ("compress", comp), ("radix-64", r64)] if on) or "none"
        self.status.configure(text=f"Saved to {path}   •   applied: {applied}   •   {len(blob)} bytes")
        dlg.show_message(self.app, "Message created",
                         f"PGP message saved to:\n{path}\n\nApplied: {applied}", "success")
