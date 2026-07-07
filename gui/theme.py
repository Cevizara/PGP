"""Single source of truth for GUI colors, as (light, dark) pairs.

customtkinter widgets accept a (light, dark) tuple for any color option and
switch automatically with ctk.set_appearance_mode(). The ttk Treeview and raw
tk widgets are NOT CTk-aware, so `pick(...)` resolves a pair to one hex for the
current mode (call it again after toggling).

Button colors follow UX color semantics:
  green  = produce / create / send   (CREATE)
  blue   = neutral primary / trust   (PRIMARY)
  red    = destructive               (DANGER)
  grey   = secondary helper actions  (NEUTRAL)
"""

import customtkinter as ctk

# --- surfaces --------------------------------------------------------------- #
WINDOW  = ("#eef1f7", "#15171c")   # app background
PANEL   = ("#ffffff", "#1b1d23")   # tabview / dialogs
CARD    = ("#e7ebf3", "#242730")   # key-table card
ROW     = ("#ffffff", "#242730")   # table row
ROW_ALT = ("#eef1f7", "#21242c")   # zebra row
HEADER  = ("#dfe4ee", "#171920")   # table heading

# --- text ------------------------------------------------------------------- #
TEXT  = ("#1f2430", "#e6e8ee")
MUTED = ("#5b6472", "#9aa3b2")

# --- semantic accents ------------------------------------------------------- #
PRIMARY      = ("#2563eb", "#3b82f6")
PRIMARY_HOV  = ("#1d4ed8", "#2563eb")
CREATE       = ("#16a34a", "#22c55e")
CREATE_HOV   = ("#15803d", "#16a34a")
DANGER       = ("#dc2626", "#ef4444")
DANGER_HOV   = ("#b91c1c", "#dc2626")
NEUTRAL      = ("#dce1ea", "#2b2f3a")
NEUTRAL_HOV  = ("#cdd4e0", "#363b48")
NEUTRAL_TEXT = ("#1f2430", "#e6e8ee")
ON_ACCENT    = "#ffffff"           # text on filled coloured buttons (both modes)

# --- status / message-box accents ------------------------------------------ #
INFO    = ("#2563eb", "#3b82f6")
SUCCESS = ("#16a34a", "#34d399")
WARN    = ("#d97706", "#fbbf24")
ERROR   = ("#dc2626", "#f87171")


def pick(pair) -> str:
    """Resolve a (light, dark) pair to one hex for the current appearance mode."""
    return pair[0] if ctk.get_appearance_mode() == "Light" else pair[1]
