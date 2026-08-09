"""Trace JSON optionnelle des evenements du protocole, pour visualisation.

Desactivee par defaut et sans cout lorsqu'elle l'est : elle ne modifie jamais
le comportement ni le resultat du protocole, seulement, si la variable
d'environnement TRACE_JSON vaut "1", elle ecrit une ligne JSON sur la sortie
standard a chaque evenement cle (reception d'un message, verification
reussie ou echouee...). Le tableau de bord de visualisation (demo/) lit ces
lignes pour animer les echanges en temps reel ; les tests et l'usage normal
n'en tiennent aucun compte.
"""

import json
import os
import time

PREFIXE = "TRACE_JSON "

_ACTIF = os.environ.get("TRACE_JSON") == "1"


def emettre(acteur, evenement, **details):
    """Ecrit un evenement de trace si TRACE_JSON=1 ; ne fait rien sinon."""
    if not _ACTIF:
        return
    ligne = {"ts": time.time(), "acteur": acteur, "evenement": evenement}
    ligne.update(details)
    print(PREFIXE + json.dumps(ligne, ensure_ascii=False), flush=True)


def hex_ou_none(valeur):
    return valeur.hex() if valeur is not None else None


def texte_ou_none(valeur):
    return valeur.decode("utf-8", errors="replace") if valeur is not None else None
