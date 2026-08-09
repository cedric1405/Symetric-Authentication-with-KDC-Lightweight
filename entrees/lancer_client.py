"""Point d'entree du conteneur client.

Charge la cle maitresse K_C montee en volume, attend que le KDC et le service
soient joignables, puis execute un nombre configurable d'echanges
d'authentification. Chaque echange complet est chronometre, ce qui fournit une
premiere mesure de latence applicative (les mesures de reference du chapitre 7
seront relevees dans l'environnement conteneurise).
"""

import os
import socket
import sys
import time

sys.path.insert(0, "/app")

from protocole.client import Client
from protocole.messages import ErreurProtocole


def charger_cle(chemin):
    with open(chemin, "r", encoding="utf-8") as fichier:
        return bytes.fromhex(fichier.read().strip())


def attendre(hote, port, delai_max=30.0):
    """Attend qu'un hote:port accepte les connexions, jusqu'a delai_max."""
    echeance = time.time() + delai_max
    while time.time() < echeance:
        try:
            with socket.create_connection((hote, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def principal():
    chemin_cle = os.environ.get("CLIENT_CLE", "/cles/K_C.key")
    id_client = os.environ.get("CLIENT_ID", "client_A").encode("utf-8")
    id_service = os.environ.get("CLIENT_SERVICE", "service_S").encode("utf-8")
    hote_kdc = os.environ.get("KDC_HOTE", "kdc")
    port_kdc = int(os.environ.get("KDC_PORT", "9001"))
    hote_service = os.environ.get("SERVICE_HOTE", "service")
    port_service = int(os.environ.get("SERVICE_PORT", "9002"))
    repetitions = int(os.environ.get("CLIENT_REPETITIONS", "1"))

    if not os.path.exists(chemin_cle):
        print("Cle du client introuvable : %s" % chemin_cle, file=sys.stderr)
        sys.exit(1)

    cle_client = charger_cle(chemin_cle)
    client = Client(id_client, cle_client, id_service)

    print("Attente du KDC (%s:%d) et du service (%s:%d)..."
          % (hote_kdc, port_kdc, hote_service, port_service))
    if not attendre(hote_kdc, port_kdc) or not attendre(hote_service, port_service):
        print("KDC ou service injoignable dans le delai imparti.", file=sys.stderr)
        sys.exit(1)

    reussites = 0
    durees = []
    for i in range(repetitions):
        debut = time.perf_counter()
        try:
            if client.authentifier(hote_kdc, port_kdc, hote_service, port_service):
                fin = time.perf_counter()
                durees.append((fin - debut) * 1000.0)  # ms
                reussites += 1
        except ErreurProtocole as erreur:
            print("Echange %d echoue : %s" % (i + 1, erreur), file=sys.stderr)

    print("Echanges reussis : %d / %d" % (reussites, repetitions))
    if durees:
        moyenne = sum(durees) / len(durees)
        print("Latence applicative : min %.2f ms, moy %.2f ms, max %.2f ms"
              % (min(durees), moyenne, max(durees)))


if __name__ == "__main__":
    principal()
