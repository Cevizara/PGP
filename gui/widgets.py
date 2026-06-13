"""Small shared GUI helpers: a dark-themed ttk.Treeview used as the key table."""

import tkinter as tk
from tkinter import ttk

# Palette (kept here so all GUI files reference one source of truth).
BG = "#1b1d23"
CARD = "#242730"
ROW = "#242730"
ROW_ALT = "#21242c"
FG = "#e6e8ee"
MUTED = "#9aa3b2"
ACCENT = "#3b82f6"
HEADER = "#171920"


def style_treeview() -> None:
    """Configure a ttk style named 'PGP.Treeview' to match the dark theme."""
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        "PGP.Treeview",
        background=ROW,
        fieldbackground=ROW,
        foreground=FG,
        rowheight=34,
        borderwidth=0,
        font=("Segoe UI", 11),
    )
    style.map(
        "PGP.Treeview",
        background=[("selected", ACCENT)],
        foreground=[("selected", "#ffffff")],
    )
    style.configure(
        "PGP.Treeview.Heading",
        background=HEADER,
        foreground=MUTED,
        relief="flat",
        font=("Segoe UI Semibold", 10),
        padding=(10, 10),
    )
    style.map("PGP.Treeview.Heading", background=[("active", HEADER)])


def make_table(parent, columns) -> ttk.Treeview:
    """columns: list of (key, heading, width, anchor)."""
    wrapper = tk.Frame(parent, bg=CARD, highlightthickness=0, bd=0)
    wrapper.pack(fill="both", expand=True, padx=2, pady=2)

    tree = ttk.Treeview(
        wrapper,
        columns=[c[0] for c in columns],
        show="headings",
        style="PGP.Treeview",
        selectmode="browse",
    )
    for key, heading, width, anchor in columns:
        tree.heading(key, text=heading, anchor=anchor)
        tree.column(key, width=width, anchor=anchor, stretch=(key == columns[0][0]))

    vsb = ttk.Scrollbar(wrapper, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")

    tree.tag_configure("odd", background=ROW_ALT)
    tree.tag_configure("even", background=ROW)
    return tree
