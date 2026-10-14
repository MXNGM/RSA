import secrets
import hashlib
import hmac
import json
import os
from math import gcd

E = 65537
HLEN = 32  # długość wyniku SHA-256 w bajtach
MALE_PIERWSZE = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def czy_pierwsza(n, rundy=40):
    if n < 2:
        return False
    for p in MALE_PIERWSZE:
        if n == p:
            return True
        if n % p == 0:
            return False

    # pan miller rzyd idzie w ruch
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rundy):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def losowa_pierwsza(bity):
    while True:
        kandydat = secrets.randbits(bity)
        kandydat |= (1 << (bity - 1)) | (1 << (bity - 2)) | 1
        if czy_pierwsza(kandydat):
            return kandydat

def generuj_klucze(bity=2048):
    while True:
        p = losowa_pierwsza(bity // 2)
        q = losowa_pierwsza(bity // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(E, phi) != 1:
            continue
        n = p * q
        d = pow(E, -1, phi)
        return (E, n), (d, n)

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def mgf1(seed, dlugosc):
    wynik, licznik = b"", 0
    while len(wynik) < dlugosc:
        wynik += hashlib.sha256(seed + licznik.to_bytes(4, "big")).digest()
        licznik += 1
    return wynik[:dlugosc]

def oaep_koduj(wiadomosc, k, etykieta=b""):
    maks = k - 2 * HLEN - 2
    if len(wiadomosc) > maks:
        raise ValueError(f"wiadomość za długa (max {maks} bajtów)")
    lhash = hashlib.sha256(etykieta).digest()
    ps = b"\x00" * (maks - len(wiadomosc))
    db = lhash + ps + b"\x01" + wiadomosc
    seed = secrets.token_bytes(HLEN)
    zamaskowany_db = xor(db, mgf1(seed, len(db)))
    zamaskowany_seed = xor(seed, mgf1(zamaskowany_db, HLEN))
    return b"\x00" + zamaskowany_seed + zamaskowany_db

def oaep_dekoduj(em, k, etykieta=b""):
    lhash = hashlib.sha256(etykieta).digest()
    zamaskowany_seed = em[1:1 + HLEN]
    zamaskowany_db = em[1 + HLEN:]
    seed = xor(zamaskowany_seed, mgf1(zamaskowany_db, HLEN))
    db = xor(zamaskowany_db, mgf1(seed, len(zamaskowany_db)))
    lhash2, reszta = db[:HLEN], db[HLEN:]
    blad = em[0] != 0
    blad |= not hmac.compare_digest(lhash, lhash2)
    i = 0
    while i < len(reszta) and reszta[i] == 0:
        i += 1
    if i == len(reszta) or reszta[i] != 1:
        blad = True
    if blad:
        raise ValueError("odszyfrowanie nieudane")
    return reszta[i + 1:]

def szyfruj(wiadomosc, klucz_pub, etykieta=b""):
    e, n = klucz_pub
    k = (n.bit_length() + 7) // 8
    em = oaep_koduj(wiadomosc, k, etykieta)
    c = pow(int.from_bytes(em, "big"), e, n)
    return c.to_bytes(k, "big")

def odszyfruj(szyfrogram, klucz_priv, etykieta=b""):
    d, n = klucz_priv
    k = (n.bit_length() + 7) // 8
    if len(szyfrogram) != k:
        raise ValueError("odszyfrowanie nieudane")
    c = int.from_bytes(szyfrogram, "big")
    if c >= n:
        raise ValueError("odszyfrowanie nieudane")
    em = pow(c, d, n).to_bytes(k, "big")
    return oaep_dekoduj(em, k, etykieta)

def generuj_klucze(bity=2048):
    while True:
        p = losowa_pierwsza(bity // 2)
        q = losowa_pierwsza(bity // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(E, phi) != 1:
            continue
        n = p * q
        d = pow(E, -1, phi)
        return (E, n), (d, n)

def wczytaj_klucz(plik):
    with open(plik, "r") as f:
        linie = f.read().splitlines()
    if len(linie) != 2:
        raise ValueError("Nieprawidłowy format klucza")
    e_d, n = map(int, linie)
    return (e_d, n)

FOLDER_KLUCZY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "klucze")

def zapisz_klucz(klucz, nazwa_pliku, prywatny=False):
    os.makedirs(FOLDER_KLUCZY, exist_ok=True)
    sciezka = os.path.join(FOLDER_KLUCZY, nazwa_pliku)
    wykladnik, n = klucz
    dane = {"wykladnik": hex(wykladnik), "n": hex(n)}
    fd = os.open(sciezka, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 0o600 if prywatny else 0o644)
    with os.fdopen(fd, "w") as f:
        json.dump(dane, f)

def wczytaj_klucz(nazwa_pliku):
    sciezka = os.path.join(FOLDER_KLUCZY, nazwa_pliku)
    with open(sciezka) as f:
        dane = json.load(f)
    return int(dane["wykladnik"], 16), int(dane["n"], 16)

# ---------- DODATKI POD GUI ----------

def klucz_na_tekst(klucz):
    """(wykładnik, n) -> 'wykładnik:n' w zapisie szesnastkowym."""
    return f"{klucz[0]:x}:{klucz[1]:x}"

def tekst_na_klucz(tekst):
    """'wykładnik:n' (hex, białe znaki ignorowane) -> (wykładnik, n)."""
    czesci = "".join(tekst.split()).split(":")
    if len(czesci) != 2:
        raise ValueError("Klucz musi mieć format wykładnik:n (hex)")
    try:
        return int(czesci[0], 16), int(czesci[1], 16)
    except ValueError:
        raise ValueError("Klucz zawiera znaki spoza zapisu szesnastkowego")

def szyfruj_kroki(wiadomosc, klucz_pub, etykieta=b""):
    """Zwraca (blok po OAEP, szyfrogram po RSA+OAEP)."""
    e, n = klucz_pub
    k = (n.bit_length() + 7) // 8
    em = oaep_koduj(wiadomosc, k, etykieta)
    c = pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big")
    return em, c

def rsa_odszyfruj_blok(szyfrogram, klucz_priv):
    """Tylko część RSA: zwraca blok OAEP (jeszcze niezdjęty)."""
    d, n = klucz_priv
    k = (n.bit_length() + 7) // 8
    if len(szyfrogram) != k:
        raise ValueError(f"Szyfrogram ma {len(szyfrogram)} B, a dla tego klucza powinien mieć {k} B")
    c = int.from_bytes(szyfrogram, "big")
    if c >= n:
        raise ValueError("Szyfrogram jest większy od n (zły klucz?)")
    return pow(c, d, n).to_bytes(k, "big")