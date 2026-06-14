from gui.app import App

STORAGE_DIR = "./keystore"


def main():
    app = App(storage_dir=STORAGE_DIR)
    app.mainloop()


if __name__ == "__main__":
    main()
