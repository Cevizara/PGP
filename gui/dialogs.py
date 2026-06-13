"""Themed modal dialogs built on customtkinter.

Each input dialog exposes `.show()` which blocks until the user submits/cancels
and returns a result dict (or None on cancel). Keeping them here keeps app.py
focused on wiring.

Layout rule: the footer (OK/Cancel) is packed BEFORE the body frame, so its
space is reserved at the bottom. If a form is taller than the window, the body
gets squeezed — never the action buttons.
"""

import customtkinter as ctk

PAD = 16


def _center(win, parent, w, h):
    parent.update_idletasks()
    px, py = parent.winfo_rootx(), parent.winfo_rooty()
    pw, ph = parent.winfo_width(), parent.winfo_height()
    x = px + (pw - w) // 2
    y = py + (ph - h) // 3
    win.geometry(f"{w}x{h}+{max(x,0)}+{max(y,0)}")


class _Modal(ctk.CTkToplevel):
    def __init__(self, parent, title, width=440, height=360):
        super().__init__(parent)
        self.result = None
        self.title(title)
        self.resizable(False, False)
        self.configure(fg_color="#1b1d23")
        _center(self, parent, width, height)
        self.transient(parent)
        # grab once the window is actually on screen (avoids Tcl "not viewable")
        self.after(120, self._safe_grab)
        self.bind("<Escape>", lambda e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _safe_grab(self):
        try:
            self.grab_set()
            self.focus_force()
        except Exception:
            pass

    def _cancel(self):
        self.result = None
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result


def _label(parent, text):
    return ctk.CTkLabel(parent, text=text, anchor="w", text_color="#9aa3b2",
                        font=ctk.CTkFont(size=12))


def _title(parent, text, subtitle=None):
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.pack(fill="x", padx=PAD, pady=(PAD, 4))
    ctk.CTkLabel(frame, text=text, anchor="w",
                 font=ctk.CTkFont(size=18, weight="bold")).pack(fill="x")
    if subtitle:
        ctk.CTkLabel(frame, text=subtitle, anchor="w", text_color="#9aa3b2",
                     font=ctk.CTkFont(size=12), justify="left").pack(fill="x", pady=(2, 0))


def _footer(parent, on_ok, ok_text="OK"):
    """Pack the action buttons at the bottom. Call this BEFORE building the body."""
    bar = ctk.CTkFrame(parent, fg_color="transparent", height=56)
    bar.pack(fill="x", side="bottom", padx=PAD, pady=PAD)
    ctk.CTkButton(bar, text=ok_text, command=on_ok, width=130, height=36).pack(side="right")
    ctk.CTkButton(bar, text="Cancel", command=parent._cancel, width=100, height=36,
                  fg_color="#2b2f3a", hover_color="#363b48").pack(side="right", padx=(0, 10))
    return bar


def _body(parent):
    body = ctk.CTkFrame(parent, fg_color="transparent")
    body.pack(fill="both", expand=True, padx=PAD, pady=4)
    return body


# --------------------------------------------------------------------------- #
# Generate key pair                                                           #
# --------------------------------------------------------------------------- #
class GenerateKeyDialog(_Modal):
    def __init__(self, parent):
        super().__init__(parent, "Generate RSA key pair", 460, 540)
        _title(self, "Generate RSA key pair",
               "Creates a new pair and stores it in your private key ring.")
        _footer(self, self._submit, "Generate")
        body = _body(self)

        _label(body, "Name").pack(fill="x")
        self.name = ctk.CTkEntry(body, placeholder_text="e.g. Aleksa Cevizovic", height=34)
        self.name.pack(fill="x", pady=(2, 10))

        _label(body, "Email").pack(fill="x")
        self.email = ctk.CTkEntry(body, placeholder_text="e.g. aleksa@example.com", height=34)
        self.email.pack(fill="x", pady=(2, 10))

        _label(body, "Key size").pack(fill="x")
        self.size = ctk.CTkSegmentedButton(body, values=["1024", "2048"])
        self.size.set("2048")
        self.size.pack(fill="x", pady=(2, 10))

        _label(body, "Passphrase (protects the private key)").pack(fill="x")
        self.pw = ctk.CTkEntry(body, show="•", height=34)
        self.pw.pack(fill="x", pady=(2, 10))

        _label(body, "Confirm passphrase").pack(fill="x")
        self.pw2 = ctk.CTkEntry(body, show="•", height=34)
        self.pw2.pack(fill="x", pady=(2, 8))

        self.err = ctk.CTkLabel(body, text="", text_color="#f87171",
                                font=ctk.CTkFont(size=12), anchor="w")
        self.err.pack(fill="x")
        self.after(160, self.name.focus_set)

    def _submit(self):
        name = self.name.get().strip()
        email = self.email.get().strip()
        pw, pw2 = self.pw.get(), self.pw2.get()
        if not name or not email:
            self.err.configure(text="Name and email are required."); return
        if not pw:
            self.err.configure(text="A passphrase is required."); return
        if pw != pw2:
            self.err.configure(text="Passphrases do not match."); return
        self.result = {"name": name, "email": email,
                       "key_size": int(self.size.get()), "passphrase": pw}
        self.destroy()


# --------------------------------------------------------------------------- #
# Ask a single passphrase                                                     #
# --------------------------------------------------------------------------- #
class PassphraseDialog(_Modal):
    def __init__(self, parent, prompt="Enter the passphrase for this private key:"):
        super().__init__(parent, "Passphrase required", 440, 270)
        _title(self, "Passphrase required", prompt)
        _footer(self, self._submit, "Unlock")
        body = _body(self)
        self.pw = ctk.CTkEntry(body, show="•", height=34)
        self.pw.pack(fill="x", pady=(8, 6))
        self.pw.bind("<Return>", lambda e: self._submit())
        self.err = ctk.CTkLabel(body, text="", text_color="#f87171",
                                font=ctk.CTkFont(size=12), anchor="w")
        self.err.pack(fill="x")
        self.after(160, self.pw.focus_set)

    def _submit(self):
        if not self.pw.get():
            self.err.configure(text="Passphrase cannot be empty."); return
        self.result = {"passphrase": self.pw.get()}
        self.destroy()


# --------------------------------------------------------------------------- #
# Import a public key (name/email + show file)                                #
# --------------------------------------------------------------------------- #
class ImportPublicDialog(_Modal):
    def __init__(self, parent, filename):
        super().__init__(parent, "Import public key", 460, 360)
        _title(self, "Import public key",
               "PEM files carry no name, so label this contact.")
        _footer(self, self._submit, "Import")
        body = _body(self)
        _label(body, "File").pack(fill="x")
        ctk.CTkLabel(body, text=filename, anchor="w",
                     font=ctk.CTkFont(size=11)).pack(fill="x", pady=(2, 10))
        _label(body, "Name").pack(fill="x")
        self.name = ctk.CTkEntry(body, height=34)
        self.name.pack(fill="x", pady=(2, 10))
        _label(body, "Email").pack(fill="x")
        self.email = ctk.CTkEntry(body, height=34)
        self.email.pack(fill="x", pady=(2, 6))
        self.err = ctk.CTkLabel(body, text="", text_color="#f87171",
                                font=ctk.CTkFont(size=12), anchor="w")
        self.err.pack(fill="x")
        self.after(160, self.name.focus_set)

    def _submit(self):
        if not self.name.get().strip() or not self.email.get().strip():
            self.err.configure(text="Name and email are required."); return
        self.result = {"name": self.name.get().strip(), "email": self.email.get().strip()}
        self.destroy()


# --------------------------------------------------------------------------- #
# Import a key pair                                                            #
# --------------------------------------------------------------------------- #
class ImportPairDialog(_Modal):
    def __init__(self, parent, filename):
        super().__init__(parent, "Import key pair", 470, 560)
        _title(self, "Import key pair",
               "Load a private-key PEM and store it under a new passphrase.")
        _footer(self, self._submit, "Import")
        body = _body(self)
        _label(body, "File").pack(fill="x")
        ctk.CTkLabel(body, text=filename, anchor="w",
                     font=ctk.CTkFont(size=11)).pack(fill="x", pady=(2, 10))
        _label(body, "File password (leave empty if the PEM is not encrypted)").pack(fill="x")
        self.filepw = ctk.CTkEntry(body, show="•", height=34)
        self.filepw.pack(fill="x", pady=(2, 10))
        _label(body, "Name").pack(fill="x")
        self.name = ctk.CTkEntry(body, height=34)
        self.name.pack(fill="x", pady=(2, 10))
        _label(body, "Email").pack(fill="x")
        self.email = ctk.CTkEntry(body, height=34)
        self.email.pack(fill="x", pady=(2, 10))
        _label(body, "New passphrase to protect it in your key ring").pack(fill="x")
        self.pw = ctk.CTkEntry(body, show="•", height=34)
        self.pw.pack(fill="x", pady=(2, 6))
        self.err = ctk.CTkLabel(body, text="", text_color="#f87171",
                                font=ctk.CTkFont(size=12), anchor="w")
        self.err.pack(fill="x")
        self.after(160, self.name.focus_set)

    def _submit(self):
        if not self.name.get().strip() or not self.email.get().strip():
            self.err.configure(text="Name and email are required."); return
        if not self.pw.get():
            self.err.configure(text="A key-ring passphrase is required."); return
        self.result = {
            "pem_password": self.filepw.get(),
            "name": self.name.get().strip(),
            "email": self.email.get().strip(),
            "keyring_passphrase": self.pw.get(),
        }
        self.destroy()


# --------------------------------------------------------------------------- #
# Export a key pair (ask keyring passphrase + optional file password)         #
# --------------------------------------------------------------------------- #
class ExportPairDialog(_Modal):
    def __init__(self, parent):
        super().__init__(parent, "Export key pair", 460, 380)
        _title(self, "Export key pair",
               "Unlock the key, then optionally protect the exported file.")
        _footer(self, self._submit, "Continue")
        body = _body(self)
        _label(body, "Key-ring passphrase (to unlock the private key)").pack(fill="x")
        self.pw = ctk.CTkEntry(body, show="•", height=34)
        self.pw.pack(fill="x", pady=(2, 10))
        _label(body, "Password for the exported file (optional but recommended)").pack(fill="x")
        self.filepw = ctk.CTkEntry(body, show="•", height=34)
        self.filepw.pack(fill="x", pady=(2, 6))
        self.err = ctk.CTkLabel(body, text="", text_color="#f87171",
                                font=ctk.CTkFont(size=12), anchor="w")
        self.err.pack(fill="x")
        self.after(160, self.pw.focus_set)

    def _submit(self):
        if not self.pw.get():
            self.err.configure(text="The key-ring passphrase is required."); return
        self.result = {"keyring_passphrase": self.pw.get(), "export_password": self.filepw.get()}
        self.destroy()


# --------------------------------------------------------------------------- #
# Simple message / confirm popups (themed)                                    #
# --------------------------------------------------------------------------- #
class _MessageBox(_Modal):
    def __init__(self, parent, title, text, kind="info", yesno=False):
        super().__init__(parent, title, 460, 240)
        colors = {"info": "#3b82f6", "error": "#f87171", "success": "#34d399",
                  "warn": "#fbbf24"}
        icons = {"info": "i", "error": "!", "success": "✓", "warn": "!"}
        accent = colors.get(kind, "#3b82f6")

        # footer first so buttons are always visible
        bar = ctk.CTkFrame(self, fg_color="transparent", height=56)
        bar.pack(fill="x", side="bottom", padx=PAD, pady=PAD)
        if yesno:
            ctk.CTkButton(bar, text="Yes", width=120, height=36, command=self._yes).pack(side="right")
            ctk.CTkButton(bar, text="No", width=90, height=36, fg_color="#2b2f3a",
                          hover_color="#363b48", command=self._cancel).pack(side="right", padx=(0, 10))
        else:
            ctk.CTkButton(bar, text="OK", width=120, height=36, command=self._ok).pack(side="right")

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=PAD, pady=(PAD, 6))
        ctk.CTkLabel(top, text=icons.get(kind, "i"), width=36, height=36,
                     corner_radius=18, fg_color=accent, text_color="#0b0d12",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(side="left")
        ctk.CTkLabel(top, text=title, anchor="w",
                     font=ctk.CTkFont(size=16, weight="bold")).pack(side="left", padx=12)

        ctk.CTkLabel(self, text=text, anchor="w", justify="left", wraplength=410,
                     text_color="#c8cdd8").pack(fill="both", expand=True, padx=PAD, pady=(0, 6))

    def _ok(self):
        self.result = True
        self.destroy()

    def _yes(self):
        self.result = True
        self.destroy()


class KeyDetailsDialog(_Modal):
    """Shows every stored field of a key-ring entry, including the public-key PEM.
    Completes requirement 3 (display rings 'with all needed information')."""

    def __init__(self, parent, entry, is_private):
        super().__init__(parent, "Key details", 560, 560)
        _title(self, entry.user_id, "Private key ring" if is_private else "Public key ring")
        bar = ctk.CTkFrame(self, fg_color="transparent", height=56)
        bar.pack(fill="x", side="bottom", padx=PAD, pady=PAD)
        ctk.CTkButton(bar, text="Close", width=120, height=36, command=self._cancel).pack(side="right")

        body = _body(self)

        def field(label, value):
            row = ctk.CTkFrame(body, fg_color="transparent"); row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=label, width=130, anchor="w",
                         text_color="#9aa3b2", font=ctk.CTkFont(size=12)).pack(side="left")
            ctk.CTkLabel(row, text=value, anchor="w", justify="left",
                         font=ctk.CTkFont(size=12)).pack(side="left", fill="x", expand=True)

        field("Name", entry.name)
        field("Email", entry.email)
        field("Key ID", entry.key_id)
        field("Fingerprint", entry.fingerprint or "—")
        field("Type / size", f"RSA {entry.key_size}-bit")
        field("Created", entry.timestamp)
        if is_private:
            algo = entry.enc_private_key.get("algo", "?")
            field("Private key", f"stored encrypted ({algo}, salted SHA-1)")
        else:
            field("Owner trust", getattr(entry, "owner_trust", "unknown"))

        ctk.CTkLabel(body, text="Public key (PEM)", anchor="w", text_color="#9aa3b2",
                     font=ctk.CTkFont(size=12)).pack(fill="x", pady=(10, 2))
        box = ctk.CTkTextbox(body, height=170, font=ctk.CTkFont(family="Consolas", size=11))
        box.pack(fill="both", expand=True)
        box.insert("1.0", entry.public_key)
        box.configure(state="disabled")


def show_message(parent, title, text, kind="info"):
    _MessageBox(parent, title, text, kind=kind).show()


def ask_yes_no(parent, title, text, kind="warn") -> bool:
    return bool(_MessageBox(parent, title, text, kind=kind, yesno=True).show())
