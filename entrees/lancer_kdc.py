"""Point d'entree du conteneur KDC.

Charge la base de cles montee en volume (jamais transmise par le reseau) et
demarre le service d'ecoute. L'adresse et le port sont lus dans les variables
d'environnement, avec des valeurs par defaut adaptees au reseau Docker.
"""

import os
import sys

sys.path.insert(0, "/app")

from protocole.kdc import BaseDeCles, KDC


def principal():
    chemin_base = os.environ.get("KDC_BASE", "/cles/base.json")
    hote = os.environ.get("KDC_HOTE", "0.0.0.0")
    port = int(os.environ.get("KDC_PORT", "9001"))

    if not os.path.exists(chemin_base):
        print("Base de cles introuvable : %s" % chemin_base, file=sys.stderr)
        print("La phase 0 d'amorcage a-t-elle ete executee ?", file=sys.stderr)
        sys.exit(1)

    base = BaseDeCles(chemin_base)
    kdc = KDC(base, hote=hote, port=port)
    print("KDC en ecoute sur %s:%d (base : %s)" % (hote, port, chemin_base))
    try:
        kdc.demarrer()
    except KeyboardInterrupt:
        kdc.arreter()


if __name__ == "__main__":
    principal()
