"""
Amorcage du deploiement : materialisation de la phase 0.

Ce script est execute une seule fois, avant tout demarrage du protocole. Il
tient le role de la phase 0 de la conception : le KDC genere les cles
maitresses, puis chacune est deposee dans un fichier propre a l'entite
concernee. Aucune cle ne transite par le reseau ; le partage se fait par le
systeme de fichiers, chaque conteneur ne montant ensuite que le fichier qui le
concerne.

Sorties, dans le repertoire passe en argument (par defaut /partage) :
    kdc/base.json    : la base complete, montee par le seul KDC
    client/K_C.key   : la cle maitresse du client, montee par le seul client
    service/K_S.key  : la cle maitresse du service, montee par le seul service

Les fichiers de cles sont ecrits avec des permissions restreintes (0600).
"""

import os
import sys

# Permet l'execution directe comme module du paquet.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocole.kdc import BaseDeCles


def ecrire_cle(chemin, cle):
    """Ecrit une cle maitresse (hex) dans un fichier en permissions 0600."""
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    descripteur = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descripteur, "w", encoding="utf-8") as fichier:
        fichier.write(cle.hex())


def amorcer(racine, id_client="client_A", id_service="service_S"):
    """Genere la base et distribue les cles dans des fichiers separes."""
    chemin_kdc = os.path.join(racine, "kdc")
    os.makedirs(chemin_kdc, exist_ok=True)

    base = BaseDeCles(os.path.join(chemin_kdc, "base.json"))
    cle_client = base.enregistrer(id_client)
    cle_service = base.enregistrer(id_service)

    ecrire_cle(os.path.join(racine, "client", "K_C.key"), cle_client)
    ecrire_cle(os.path.join(racine, "service", "K_S.key"), cle_service)

    print("Phase 0 accomplie.")
    print("  base du KDC   : %s" % os.path.join(chemin_kdc, "base.json"))
    print("  cle du client : %s" % os.path.join(racine, "client", "K_C.key"))
    print("  cle du service: %s" % os.path.join(racine, "service", "K_S.key"))
    print("  identites     : %s, %s" % (id_client, id_service))


if __name__ == "__main__":
    racine = sys.argv[1] if len(sys.argv) > 1 else "/partage"
    amorcer(racine)
