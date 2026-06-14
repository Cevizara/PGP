"""Main application window.

Layout:
  - header (title + subtitle)
  - tab view: "My Keys" (private ring) and "Contacts" (public ring)
  - each tab: a toolbar of actions + a key table
  - status bar at the bottom

The window owns one KeyManager and refreshes the tables after every action.
"""

import os
from tkinter import filedialog

import customtkinter as ctk

from pgp.keymanager import KeyManager
from pgp.errors import PGPError, WrongPassphrase

from .widgets import style_treeview, make_table
from .send_view import SendView
from .receive_view import ReceiveView
from . import dialogs as dlg

DEFAULT_STORAGE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keystore")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

PRIVATE_COLUMNS = [
    ("user", "Owner", 220, "w"),
    ("email", "Email", 200, "w"),
    ("key_id", "Key ID", 150, "w"),
    ("bits", "Bits", 60, "center"),
    ("created", "Created", 110, "center"),
]
PUBLIC_COLUMNS = [
    ("user", "Owner", 220, "w"),
    ("email", "Email", 200, "w"),
    ("key_id", "Key ID", 150, "w"),
    ("bits", "Bits", 60, "center"),
    ("created", "Created", 110, "center"),
]


class App(ctk.CTk):
    def __init__(self, storage_dir=None):
        super().__init__()
        self.storage_dir = storage_dir or DEFAULT_STORAGE_DIR
        # Show the keystore folder in the title so two demo instances are
        # immediately distinguishable side by side.
        self.title(f"PGP — Zaštita podataka   [{os.path.basename(self.storage_dir)}]")
        self.geometry("980x640")
        self.minsize(860, 560)
        self.configure(fg_color="#15171c")

        self.km = KeyManager(self.storage_dir)
        style_treeview()

        self._build_header()
        self._build_tabs()
        self._build_statusbar()

        self.refresh_private()
        self.refresh_public()

    # ------------------------------------------------------------------ #
    # Layout                                                              #
    # ------------------------------------------------------------------ #
    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent", height=64)
        header.pack(fill="x", padx=20, pady=(18, 6))
        ctk.CTkLabel(header, text=f"PGP Key Manager  ·  {os.path.basename(self.storage_dir)}",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(header, text="Keys · exchange · sign · encrypt · decrypt · verify  •  Zaštita podataka 2025/26",
                     text_color="#9aa3b2", font=ctk.CTkFont(size=12)).pack(anchor="w")

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(self, fg_color="#1b1d23",
                                   segmented_button_selected_color="#3b82f6",
                                   command=self._on_tab_change)
        self.tabs.pack(fill="both", expand=True, padx=20, pady=10)
        self.tab_private = self.tabs.add("  My Keys  ")
        self.tab_public = self.tabs.add("  Contacts  ")
        self.tab_send = self.tabs.add("  Send  ")
        self.tab_receive = self.tabs.add("  Receive  ")

        self.tree_private = self._build_private_tab(self.tab_private)
        self.tree_public = self._build_public_tab(self.tab_public)

        self.send_view = SendView(self.tab_send, self)
        self.send_view.pack(fill="both", expand=True, padx=6, pady=6)
        self.receive_view = ReceiveView(self.tab_receive, self)
        self.receive_view.pack(fill="both", expand=True, padx=6, pady=6)

    def _on_tab_change(self):
        # keep the Send dropdowns in sync with the current rings
        if self.tabs.get().strip() == "Send":
            self.send_view.refresh()

    def _toolbar(self, parent):
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.pack(fill="x", padx=6, pady=(8, 6))
        return bar

    def _btn(self, bar, text, command, primary=False):
        return ctk.CTkButton(
            bar, text=text, command=command, height=34, corner_radius=8,
            fg_color="#3b82f6" if primary else "#2b2f3a",
            hover_color="#2563eb" if primary else "#363b48",
            font=ctk.CTkFont(size=12, weight="bold" if primary else "normal"),
        )

    def _build_private_tab(self, parent):
        bar = self._toolbar(parent)
        self._btn(bar, "+  Generate", self.on_generate, primary=True).pack(side="left", padx=(0, 8))
        self._btn(bar, "Import pair", self.on_import_pair).pack(side="left", padx=4)
        self._btn(bar, "Export public", lambda: self.on_export_public("private")).pack(side="left", padx=4)
        self._btn(bar, "Export pair", self.on_export_pair).pack(side="left", padx=4)
        self._btn(bar, "Details", lambda: self.on_details("private")).pack(side="left", padx=4)
        self._btn(bar, "Delete", self.on_delete_private).pack(side="left", padx=4)

        card = ctk.CTkFrame(parent, fg_color="#242730", corner_radius=10)
        card.pack(fill="both", expand=True, padx=6, pady=(2, 8))
        tree = make_table(card, PRIVATE_COLUMNS)
        tree.bind("<<TreeviewSelect>>", lambda e: self._update_status_from_selection(tree, "private"))
        tree.bind("<Double-1>", lambda e: self.on_details("private"))
        return tree

    def _build_public_tab(self, parent):
        bar = self._toolbar(parent)
        self._btn(bar, "+  Import public", self.on_import_public, primary=True).pack(side="left", padx=(0, 8))
        self._btn(bar, "Export public", lambda: self.on_export_public("public")).pack(side="left", padx=4)
        self._btn(bar, "Details", lambda: self.on_details("public")).pack(side="left", padx=4)
        self._btn(bar, "Delete", self.on_delete_public).pack(side="left", padx=4)

        card = ctk.CTkFrame(parent, fg_color="#242730", corner_radius=10)
        card.pack(fill="both", expand=True, padx=6, pady=(2, 8))
        tree = make_table(card, PUBLIC_COLUMNS)
        tree.bind("<<TreeviewSelect>>", lambda e: self._update_status_from_selection(tree, "public"))
        tree.bind("<Double-1>", lambda e: self.on_details("public"))
        return tree

    def _build_statusbar(self):
        self.status = ctk.CTkLabel(self, text="Ready", anchor="w", text_color="#9aa3b2",
                                   font=ctk.CTkFont(size=12))
        self.status.pack(fill="x", padx=24, pady=(0, 12))

    def set_status(self, text):
        self.status.configure(text=text)

    # ------------------------------------------------------------------ #
    # Table refresh / selection                                          #
    # ------------------------------------------------------------------ #
    def _fill(self, tree, entries):
        tree.delete(*tree.get_children())
        for i, e in enumerate(entries):
            tag = "even" if i % 2 == 0 else "odd"
            tree.insert("", "end", iid=e.key_id, tags=(tag,), values=(
                e.name, e.email, e.key_id, e.key_size, e.timestamp[:10],
            ))

    def refresh_private(self):
        self._fill(self.tree_private, list(self.km.private_ring))
        self.set_status(f"{len(self.km.private_ring)} key pair(s) in your private ring.")

    def refresh_public(self):
        self._fill(self.tree_public, list(self.km.public_ring))

    def _selected(self, tree):
        sel = tree.selection()
        return sel[0] if sel else None

    def _update_status_from_selection(self, tree, ring):
        key_id = self._selected(tree)
        if not key_id:
            return
        source = self.km.private_ring if ring == "private" else self.km.public_ring
        entry = source.get(key_id)
        if entry:
            self.set_status(f"Selected: {entry.user_id}   •   Key ID {entry.key_id}")

    def _require_selection(self, tree, what):
        key_id = self._selected(tree)
        if not key_id:
            dlg.show_message(self, "Nothing selected", f"Select a key first to {what}.", "warn")
            return None
        return key_id

    def on_details(self, ring):
        tree = self.tree_private if ring == "private" else self.tree_public
        key_id = self._require_selection(tree, "see its details")
        if not key_id:
            return
        source = self.km.private_ring if ring == "private" else self.km.public_ring
        entry = source.get(key_id)
        if entry:
            dlg.KeyDetailsDialog(self, entry, is_private=(ring == "private")).show()

    # ------------------------------------------------------------------ #
    # Actions — private ring                                             #
    # ------------------------------------------------------------------ #
    def on_generate(self):
        data = dlg.GenerateKeyDialog(self).show()
        if not data:
            return
        try:
            entry = self.km.generate_keypair(
                data["name"], data["email"], data["key_size"], data["passphrase"])
        except PGPError as exc:
            dlg.show_message(self, "Error", str(exc), "error"); return
        self.refresh_private()
        dlg.show_message(self, "Key pair generated",
                         f"Created a {entry.key_size}-bit RSA key for {entry.user_id}.\n\n"
                         f"Key ID: {entry.key_id}", "success")

    def on_delete_private(self):
        key_id = self._require_selection(self.tree_private, "delete it")
        if not key_id:
            return
        entry = self.km.private_ring.get(key_id)
        if not dlg.ask_yes_no(self, "Delete key pair",
                              f"Permanently delete the key pair for {entry.user_id}?\n"
                              "This cannot be undone."):
            return
        self.km.delete_private_key(key_id)
        self.refresh_private()
        self.set_status(f"Deleted key {key_id}.")

    def on_export_public(self, ring):
        tree = self.tree_private if ring == "private" else self.tree_public
        key_id = self._require_selection(tree, "export it")
        if not key_id:
            return
        source = self.km.private_ring if ring == "private" else self.km.public_ring
        entry = source.get(key_id)
        path = filedialog.asksaveasfilename(
            title="Export public key", defaultextension=".pem",
            initialfile=f"{entry.name.replace(' ', '_')}_public.pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if not path:
            return
        try:
            self.km.export_public_key(key_id, path)
        except PGPError as exc:
            dlg.show_message(self, "Error", str(exc), "error"); return
        self.set_status(f"Exported public key to {path}")
        dlg.show_message(self, "Exported", f"Public key saved to:\n{path}", "success")

    def on_export_pair(self):
        key_id = self._require_selection(self.tree_private, "export it")
        if not key_id:
            return
        data = dlg.ExportPairDialog(self).show()
        if not data:
            return
        if not self.km.verify_passphrase(key_id, data["keyring_passphrase"]):
            dlg.show_message(self, "Wrong passphrase",
                             "The key-ring passphrase is incorrect.", "error"); return
        entry = self.km.private_ring.get(key_id)
        path = filedialog.asksaveasfilename(
            title="Export key pair", defaultextension=".pem",
            initialfile=f"{entry.name.replace(' ', '_')}_keypair.pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if not path:
            return
        try:
            self.km.export_keypair(key_id, data["keyring_passphrase"], path,
                                   export_password=data["export_password"] or None)
        except WrongPassphrase:
            dlg.show_message(self, "Wrong passphrase",
                             "The key-ring passphrase is incorrect.", "error"); return
        except PGPError as exc:
            dlg.show_message(self, "Error", str(exc), "error"); return
        protected = "password-protected " if data["export_password"] else ""
        self.set_status(f"Exported {protected}key pair to {path}")
        dlg.show_message(self, "Exported", f"{protected.capitalize()}key pair saved to:\n{path}",
                         "success")

    def on_import_pair(self):
        path = filedialog.askopenfilename(
            title="Import key pair (private-key PEM)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if not path:
            return
        data = dlg.ImportPairDialog(self, os.path.basename(path)).show()
        if not data:
            return
        try:
            entry = self.km.import_keypair(path, data["pem_password"], data["name"],
                                           data["email"], data["keyring_passphrase"])
        except PGPError as exc:
            dlg.show_message(self, "Import failed", str(exc), "error"); return
        self.refresh_private()
        dlg.show_message(self, "Imported", f"Key pair for {entry.user_id} added.\n"
                         f"Key ID: {entry.key_id}", "success")

    # ------------------------------------------------------------------ #
    # Actions — public ring                                              #
    # ------------------------------------------------------------------ #
    def on_import_public(self):
        path = filedialog.askopenfilename(
            title="Import public key (PEM)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if not path:
            return
        data = dlg.ImportPublicDialog(self, os.path.basename(path)).show()
        if not data:
            return
        try:
            entry = self.km.import_public_key(path, data["name"], data["email"])
        except PGPError as exc:
            dlg.show_message(self, "Import failed", str(exc), "error"); return
        self.refresh_public()
        dlg.show_message(self, "Imported", f"Public key for {entry.user_id} added.\n"
                         f"Key ID: {entry.key_id}", "success")

    def on_delete_public(self):
        key_id = self._require_selection(self.tree_public, "delete it")
        if not key_id:
            return
        entry = self.km.public_ring.get(key_id)
        if not dlg.ask_yes_no(self, "Delete contact key",
                              f"Remove the public key for {entry.user_id}?"):
            return
        self.km.delete_public_key(key_id)
        self.refresh_public()
        self.set_status(f"Deleted public key {key_id}.")
