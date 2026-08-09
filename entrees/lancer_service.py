"""Point d'entree du conteneur service.

Charge la cle maitresse K_S montee en volume et demarre le serveur applicatif,
qui verifie l'authentification des clients et tient le cache anti-rejeu.
"""

import os
import sys

sys.path.insert(0, "/app")

from protocole.service import Service


def charger_cle(chemin):
    with open(chemin, "r", encoding="utf-8") as fichier:
        return bytes.fromhex(fichier.read().strip())


def principal():
    chemin_cle = os.environ.get("SERVICE_CLE", "/cles/K_S.key")
    id_service = os.environ.get("SERVICE_ID", "service_S").encode("utf-8")
    hote = os.environ.get("SERVICE_HOTE", "0.0.0.0")
    port = int(os.environ.get("SERVICE_PORT", "9002"))

    if not os.path.exists(chemin_cle):
        print("Cle du service introuvable : %s" % chemin_cle, file=sys.stderr)
        sys.exit(1)

    cle_service = charger_cle(chemin_cle)
    service = Service(id_service, cle_service, hote=hote, port=port)
    print("Service '%s' en ecoute sur %s:%d"
          % (id_service.decode(), hote, port))
    try:
        service.demarrer()
    except KeyboardInterrupt:
        service.arreter()


if __name__ == "__main__":
    principal()
