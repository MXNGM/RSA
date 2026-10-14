import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from rsa import (
    generuj_klucze, zapisz_klucz, wczytaj_klucz,
    klucz_na_tekst, tekst_na_klucz,
    szyfruj_kroki, rsa_odszyfruj_blok, oaep_dekoduj,
)

CZCIONKA_POL = ("Consolas", 9)


def pobierz(pole):
    return pole.get("1.0", "end-1c")


def ustaw(pole, zawartosc):
    stan = pole.cget("state")
    pole.configure(state="normal")
    pole.delete("1.0", "end")
    pole.insert("1.0", zawartosc)
    pole.configure(state=stan)


def kopiuj(pole):
    pole.clipboard_clear()
    pole.clipboard_append(pobierz(pole))


def pole_tekstowe(rodzic, tytul, wysokosc, tylko_odczyt=False):
    ramka = ttk.Frame(rodzic)
    ramka.pack(fill="both", expand=True, pady=(8, 0))

    gora = ttk.Frame(ramka)
    gora.pack(fill="x")
    ttk.Label(gora, text=tytul).pack(side="left")

    srodek = ttk.Frame(ramka)
    srodek.pack(fill="both", expand=True, pady=(2, 0))
    pole = tk.Text(srodek, height=wysokosc, wrap="char", font=CZCIONKA_POL, undo=True)
    pasek = ttk.Scrollbar(srodek, command=pole.yview)
    pole.configure(yscrollcommand=pasek.set)
    pasek.pack(side="right", fill="y")
    pole.pack(side="left", fill="both", expand=True)

    ttk.Button(gora, text="Kopiuj", command=lambda: kopiuj(pole)).pack(side="right")
    if tylko_odczyt:
        pole.configure(state="disabled")
    return pole


class Aplikacja:
    def __init__(self, root):
        self.root = root
        root.title("RSA + OAEP")
        root.geometry("1150x760")
        root.minsize(900, 600)

        styl = ttk.Style()
        for motyw in ("vista", "winnative", "clam"):
            if motyw in styl.theme_names():
                styl.theme_use(motyw)
                break

        self.status = tk.StringVar(value="Gotowe")
        ttk.Label(root, textvariable=self.status, relief="sunken", anchor="w",
                  padding=(6, 2)).pack(side="bottom", fill="x")

        panel = ttk.PanedWindow(root, orient="horizontal")
        panel.pack(fill="both", expand=True, padx=8, pady=8)
        lewa = ttk.LabelFrame(panel, text=" Kodowanie ", padding=8)
        prawa = ttk.LabelFrame(panel, text=" Dekodowanie ", padding=8)
        panel.add(lewa, weight=1)
        panel.add(prawa, weight=1)

        self.buduj_lewa(lewa)
        self.buduj_prawa(prawa)

    # ---------- lewa połowa ----------

    def buduj_lewa(self, p):
        wiersz = ttk.Frame(p)
        wiersz.pack(fill="x")
        ttk.Label(wiersz, text="Rozmiar klucza (bity):").pack(side="left")
        self.bity = tk.StringVar(value="2048")
        ttk.Combobox(wiersz, textvariable=self.bity, values=("1024", "2048", "3072"),
                     width=6, state="readonly").pack(side="left", padx=6)
        self.btn_gen = ttk.Button(wiersz, text="Generuj klucze", command=self.generuj)
        self.btn_gen.pack(side="left")

        self.pole_pub = pole_tekstowe(p, "Klucz publiczny (e:n, hex)", 3)
        self.pole_priv = pole_tekstowe(p, "Klucz prywatny (d:n, hex), nikomu nie pokazuj", 3)

        wiersz2 = ttk.Frame(p)
        wiersz2.pack(fill="x", pady=(8, 0))
        ttk.Button(wiersz2, text="Zapisz klucze do folderu klucze",
                   command=self.zapisz).pack(side="left")
        ttk.Button(wiersz2, text="Wczytaj klucze z folderu klucze",
                   command=self.wczytaj).pack(side="left", padx=6)

        self.pole_msg = pole_tekstowe(p, "Wiadomość do zakodowania", 3)
        ttk.Button(p, text="Zakoduj", command=self.zakoduj).pack(anchor="w", pady=(8, 0))

        self.out_oaep = pole_tekstowe(p, "Po OAEP (blok przed RSA, hex)", 4, tylko_odczyt=True)
        self.out_rsa = pole_tekstowe(p, "Po RSA + OAEP (szyfrogram, hex)", 4, tylko_odczyt=True)

    # ---------- prawa połowa ----------

    def buduj_prawa(self, p):
        self.pole_priv_dek = pole_tekstowe(p, "Klucz prywatny (d:n, hex)", 3)
        self.pole_szyfr = pole_tekstowe(p, "Zakodowany tekst do odkodowania (hex), wklej tutaj", 8)
        ttk.Button(p, text="Odkoduj", command=self.odkoduj).pack(anchor="w", pady=(8, 0))
        self.out_blok = pole_tekstowe(p, "Po odszyfrowaniu samego RSA (blok OAEP, hex)", 6,
                                      tylko_odczyt=True)
        self.out_wynik = pole_tekstowe(p, "Po zdjęciu OAEP (odczytana wiadomość)", 4,
                                       tylko_odczyt=True)

    # ---------- akcje ----------

    def blad(self, tresc):
        self.status.set("Błąd: " + tresc)
        messagebox.showerror("Błąd", tresc)

    def ustaw_klucze(self, pub, priv):
        ustaw(self.pole_pub, klucz_na_tekst(pub))
        ustaw(self.pole_priv, klucz_na_tekst(priv))
        ustaw(self.pole_priv_dek, klucz_na_tekst(priv))

    def generuj(self):
        bity = int(self.bity.get())
        self.btn_gen.configure(state="disabled")
        self.status.set(f"Generuję klucz {bity}-bitowy, to może potrwać...")
        kolejka = queue.Queue()

        def praca():
            try:
                kolejka.put(("ok", generuj_klucze(bity)))
            except Exception as ex:
                kolejka.put(("blad", ex))

        threading.Thread(target=praca, daemon=True).start()
        self.root.after(100, lambda: self.sprawdz_generowanie(kolejka))

    def sprawdz_generowanie(self, kolejka):
        try:
            rodzaj, wynik = kolejka.get_nowait()
        except queue.Empty:
            self.root.after(100, lambda: self.sprawdz_generowanie(kolejka))
            return
        self.btn_gen.configure(state="normal")
        if rodzaj == "ok":
            pub, priv = wynik
            self.ustaw_klucze(pub, priv)
            self.status.set(f"Wygenerowano klucz {pub[1].bit_length()}-bitowy")
        else:
            self.blad(str(wynik))

    def zapisz(self):
        try:
            pub = tekst_na_klucz(pobierz(self.pole_pub))
            priv = tekst_na_klucz(pobierz(self.pole_priv))
            zapisz_klucz(pub, "publiczny.json")
            zapisz_klucz(priv, "prywatny.json", prywatny=True)
        except (ValueError, OSError) as ex:
            self.blad(str(ex))
            return
        self.status.set("Zapisano klucze w folderze klucze")

    def wczytaj(self):
        try:
            pub = wczytaj_klucz("publiczny.json")
            priv = wczytaj_klucz("prywatny.json")
        except (OSError, ValueError, KeyError) as ex:
            self.blad(f"Nie udało się wczytać kluczy: {ex}")
            return
        self.ustaw_klucze(pub, priv)
        self.status.set("Wczytano klucze z folderu klucze")

    def zakoduj(self):
        ustaw(self.out_oaep, "")
        ustaw(self.out_rsa, "")
        try:
            pub = tekst_na_klucz(pobierz(self.pole_pub))
            wiadomosc = pobierz(self.pole_msg).encode("utf-8")
            em, c = szyfruj_kroki(wiadomosc, pub)
        except ValueError as ex:
            self.blad(str(ex))
            return
        ustaw(self.out_oaep, em.hex())
        ustaw(self.out_rsa, c.hex())
        self.status.set(f"Zakodowano {len(wiadomosc)} B wiadomości")

    def odkoduj(self):
        ustaw(self.out_blok, "")
        ustaw(self.out_wynik, "")
        try:
            priv = tekst_na_klucz(pobierz(self.pole_priv_dek))
            szyfrogram = bytes.fromhex(pobierz(self.pole_szyfr))
        except ValueError as ex:
            self.blad(f"Zły klucz lub ciąg (musi być hex): {ex}")
            return
        try:
            em = rsa_odszyfruj_blok(szyfrogram, priv)
        except ValueError as ex:
            self.blad(str(ex))
            return
        ustaw(self.out_blok, em.hex())
        k = (priv[1].bit_length() + 7) // 8
        try:
            wiadomosc = oaep_dekoduj(em, k)
            ustaw(self.out_wynik, wiadomosc.decode("utf-8"))
        except UnicodeDecodeError:
            self.blad("OAEP przeszło, ale wiadomość nie jest poprawnym tekstem UTF-8")
            return
        except ValueError:
            self.blad("OAEP odrzucone: zły klucz albo uszkodzony szyfrogram")
            return
        self.status.set("Odkodowano poprawnie")


if __name__ == "__main__":
    root = tk.Tk()
    Aplikacja(root)
    root.mainloop()