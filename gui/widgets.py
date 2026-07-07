"""Small shared GUI helpers: a themed ttk.Treeview used as the key table.

The ttk Treeview is not customtkinter-aware, so its colours are resolved from
`theme` for the current appearance mode. Call `style_treeview()` and
`restyle_table()` again after toggling the theme to refresh them.
"""

import tkinter as tk
from tkinter import ttk

from . import theme


def style_treeview() -> None:
    """Configure the ttk style 'PGP.Treeview' for the current appearance mode."""
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    row = theme.pick(theme.ROW)
    fg = theme.pick(theme.TEXT)
    header = theme.pick(theme.HEADER)
    muted = theme.pick(theme.MUTED)
    accent = theme.pick(theme.PRIMARY)

    style.configure(
        "PGP.Treeview",
        background=row,
        fieldbackground=row,
        foreground=fg,
        rowheight=34,
        borderwidth=0,
        font=("Segoe UI", 11),
    )
    style.map(
        "PGP.Treeview",
        background=[("selected", accent)],
        foreground=[("selected", "#ffffff")],
    )
    style.configure(
        "PGP.Treeview.Heading",
        background=header,
        foreground=muted,
        relief="flat",
        font=("Segoe UI Semibold", 10),
        padding=(10, 10),
    )
    style.map("PGP.Treeview.Heading", background=[("active", header)])


def restyle_table(tree: ttk.Treeview) -> None:
    """Re-apply the per-tree colours (zebra rows + wrapper) after a theme change."""
    tree.tag_configure("odd", background=theme.pick(theme.ROW_ALT))
    tree.tag_configure("even", background=theme.pick(theme.ROW))
    wrapper = getattr(tree, "pgp_wrapper", None)
    if wrapper is not None:
        wrapper.configure(bg=theme.pick(theme.CARD))


def make_table(parent, columns) -> ttk.Treeview:
    """columns: list of (key, heading, width, anchor)."""
    wrapper = tk.Frame(parent, bg=theme.pick(theme.CARD), highlightthickness=0, bd=0)
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

    tree.pgp_wrapper = wrapper          # kept so the theme toggle can recolour it
    tree.tag_configure("odd", background=theme.pick(theme.ROW_ALT))
    tree.tag_configure("even", background=theme.pick(theme.ROW))
    return tree
