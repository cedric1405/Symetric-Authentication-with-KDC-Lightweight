"""
Mesure de la montee en charge : capacite reelle du deploiement.

`mesures.py` mesure un seul client sequentiel : cela etablit un plancher de
latence, pas une capacite. Ce script cherche le palier de clients concurrents
ou le debit agrege cesse de croitre et la latence par authentification se
degrade — c'est cette valeur, et non le debit sequentiel, qui repond a la
question « combien de clients/services le protocole supporte-t-il a la
fois ? ».

Methodologie (voir CONTEXTE_REPRISE.md, chantier 2) :
  - mesure ENTRE CONTENEURS (kdc:9001/service:9002, par leurs noms sur le
    reseau Docker), jamais via les ports publies vers l'hote : le relai de
    Docker Desktop ajoute un cout par connexion qui fausserait le point de
    saturation observe (deja etabli au chapitre 7) ;
  - trace JSON INACTIVE (TRACE_JSON=0) : son cout mesure (chapitre 7 : plus
    du double de latence) provoquerait une fausse saturation ;
  - le point de saturation est OBSERVE ici, jamais extrapole depuis le seul
    CPU. Le CPU/RAM se relevent en parallele (docker stats, voir plus bas)
    pour SITUER la saturation, pas pour la deduire par le calcul.

A chaque palier N, N clients concurrents (fils) authentifient en boucle
pendant une duree fixe ; le script releve le debit agrege, la latence
mediane et p95 par authentification reussie, et le taux d'echec.

Limite assumee : les N fils partagent la MEME identite enregistree
(--id-client) plutot que N identites distinctes. Le protocole n'offre pas de
canal d'enregistrement en ligne — les identites sont creees hors reseau, par
la phase 0 (amorce/phase0.py) — donc simuler N clients enregistres
distinctement demanderait de reamorcer le KDC avec N identites puis de
redemarrer le conteneur. Chaque fil ouvre neanmoins ses propres connexions et
sa propre session (nonce frais a chaque authentification), ce qui teste bien
N authentifications concurrentes sur le KDC et le service : c'est la charge
cote serveur qui interesse ce chantier, pas la diversite des identites.

Pour situer la saturation cote ressources, ouvrir en parallele, dans un
second terminal, sur toute la duree du test :

    docker stats kdc_prototype-kdc-1 kdc_prototype-service-1

et noter les valeurs observees pendant la fenetre horaire de chaque palier
(affichee par ce script au fil de l'execution).

Usage, depuis l'interieur du reseau Docker (le script doit resoudre les noms
kdc/service : il doit donc s'executer dans un conteneur du meme reseau) :

    docker compose run --rm -e TRACE_JSON=0 \\
        -v "$(pwd)/mesures_charge.py:/app/mesures_charge.py" client \\
        python /app/mesures_charge.py --cle /cles/K_C.key \\
        --kdc kdc:9001 --service service:9002 \\
        --niveaux 1,5,10,20,50 --duree 10
"""

import argparse
import math
import sys
import threading
import time

sys.path.insert(0, "/app")

from protocole.client import Client
from protocole.messages import ErreurProtocole


# --- Statistiques -------------------------------------------------------

def statistiques(valeurs):
    """Retourne min/mediane/moyenne/p95/max (en ms), ou None si vide."""
    if not valeurs:
        return None
    triees = sorted(valeurs)
    n = len(triees)

    def percentile(p):
        if n == 1:
            return triees[0]
        rang = p / 100.0 * (n - 1)
        bas, haut = int(math.floor(rang)), int(math.ceil(rang))
        if bas == haut:
            return triees[bas]
        poids = rang - bas
        return triees[bas] * (1 - poids) + triees[haut] * poids

    return {
        "n": n,
        "min": triees[0],
        "mediane": percentile(50),
        "moyenne": sum(triees) / n,
        "p95": percentile(95),
        "max": triees[-1],
    }


def charger_cle(chemin):
    with open(chemin, "r", encoding="utf-8") as fichier:
        return bytes.fromhex(fichier.read().strip())


def separer_hote_port(chaine):
    hote, port = chaine.rsplit(":", 1)
    return hote, int(port)


# --- Un palier de charge -------------------------------------------------

def executer_niveau(n_clients, duree, cle_client, id_client, id_service,
                     hote_kdc, port_kdc, hote_service, port_service):
    """Fait authentifier N clients concurrents en boucle pendant `duree`
    secondes. Retourne (resultats, debut_horloge, fin_horloge), ou resultats
    est la liste de (succes: bool, latence_ms: float) de chaque tentative.
    """
    resultats = []
    verrou = threading.Lock()
    arret = threading.Event()

    def travailleur():
        client = Client(id_client, cle_client, id_service)
        locaux = []
        while not arret.is_set():
            debut = time.perf_counter()
            try:
                client.authentifier(
                    hote_kdc, port_kdc, hote_service, port_service
                )
                locaux.append((True, (time.perf_counter() - debut) * 1000.0))
            except ErreurProtocole:
                locaux.append((False, (time.perf_counter() - debut) * 1000.0))
        with verrou:
            resultats.extend(locaux)

    fils = [threading.Thread(target=travailleur) for _ in range(n_clients)]
    debut_horloge = time.strftime("%H:%M:%S")
    for f in fils:
        f.start()
    time.sleep(duree)
    arret.set()
    for f in fils:
        f.join()
    fin_horloge = time.strftime("%H:%M:%S")

    return resultats, debut_horloge, fin_horloge


def afficher_niveau(n_clients, duree, resultats, debut_horloge, fin_horloge):
    reussites = [lat for ok, lat in resultats if ok]
    echecs = [lat for ok, lat in resultats if not ok]
    total = len(resultats)
    debit = len(reussites) / duree

    print("=" * 64)
    print("Palier N = %d clients concurrents (%s -> %s)"
          % (n_clients, debut_horloge, fin_horloge))
    print("=" * 64)
    print("  authentifications : %d reussies, %d echouees (sur %d tentees)"
          % (len(reussites), len(echecs), total))
    print("  taux d'echec      : %.2f %%"
          % (100.0 * len(echecs) / total if total else 0.0))
    print("  debit agrege      : %.1f authentifications / seconde" % debit)
    stats = statistiques(reussites)
    if stats:
        print("  latence (reussies, n=%d) : mediane %.2f ms, "
              "p95 %.2f ms, max %.2f ms"
              % (stats["n"], stats["mediane"], stats["p95"], stats["max"]))
    print("  -> relever docker stats sur cette fenetre pour le CPU/RAM.")
    print()

    return {
        "n_clients": n_clients,
        "debit": debit,
        "taux_echec": 100.0 * len(echecs) / total if total else 0.0,
        "latence_mediane": stats["mediane"] if stats else None,
        "latence_p95": stats["p95"] if stats else None,
    }


# --- Programme principal --------------------------------------------------

def principal():
    analyseur = argparse.ArgumentParser(
        description="Montee en charge : capacite reelle du deploiement."
    )
    analyseur.add_argument("--cle", required=True,
                            help="fichier de la cle maitresse du client")
    analyseur.add_argument("--kdc", default="kdc:9001", help="hote:port du KDC")
    analyseur.add_argument("--service", default="service:9002",
                            help="hote:port du service")
    analyseur.add_argument("--id-client", default="client_A")
    analyseur.add_argument("--id-service", default="service_S")
    analyseur.add_argument("--niveaux", default="1,5,10,20,50",
                            help="paliers de clients concurrents, "
                                 "separes par des virgules")
    analyseur.add_argument("--duree", type=float, default=10.0,
                            help="duree en secondes de chaque palier")
    args = analyseur.parse_args()

    cle_client = charger_cle(args.cle)
    id_client = args.id_client.encode("utf-8")
    id_service = args.id_service.encode("utf-8")
    hote_kdc, port_kdc = separer_hote_port(args.kdc)
    hote_service, port_service = separer_hote_port(args.service)
    niveaux = [int(n) for n in args.niveaux.split(",")]

    print("Montee en charge : paliers %s, %.1f s chacun." % (niveaux, args.duree))
    print("Rappel methodologique : mesure entre conteneurs, trace inactive.")
    print("Ouvrir en parallele : docker stats <conteneur-kdc> <conteneur-service>")
    print()

    recapitulatif = []
    for n in niveaux:
        resultats, debut_horloge, fin_horloge = executer_niveau(
            n, args.duree, cle_client, id_client, id_service,
            hote_kdc, port_kdc, hote_service, port_service,
        )
        recapitulatif.append(
            afficher_niveau(n, args.duree, resultats, debut_horloge, fin_horloge)
        )

    print("=" * 64)
    print("RECAPITULATIF")
    print("=" * 64)
    print("%-6s %16s %14s %12s %12s"
          % ("N", "debit (auth/s)", "mediane (ms)", "p95 (ms)", "echecs (%)"))
    for ligne in recapitulatif:
        mediane = ("%.2f" % ligne["latence_mediane"]
                   if ligne["latence_mediane"] is not None else "-")
        p95 = ("%.2f" % ligne["latence_p95"]
               if ligne["latence_p95"] is not None else "-")
        print("%-6d %16.1f %14s %12s %12.2f" % (
            ligne["n_clients"], ligne["debit"], mediane, p95, ligne["taux_echec"]
        ))
    print()
    print("Le palier ou le debit cesse de croitre et la latence decroche est")
    print("la capacite reelle du deploiement — a comparer au debit sequentiel")
    print("(un seul client, deja mesure au chapitre 7).")


if __name__ == "__main__":
    principal()
