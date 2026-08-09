"""
Mesure des performances du prototole.

Ce script alimente le chapitre 7 (resultats). Il ne se contente pas d'une
moyenne, trompeuse a elle seule, mais releve une distribution complete :
minimum, mediane, moyenne, ecart-type, 95e et 99e percentiles, maximum. Les
premiers echanges, gonfles par la phase de chauffe (etablissement des
connexions, demarrage des fils), sont mesures a part et exclus des statistiques
de regime permanent.

Trois mesures distinctes, pour trois questions :

    1. Latence de bout en bout : duree d'un echange complet (les six etapes).
       Repond a l'hypothese H2 sur la compatibilite avec un usage reel.

    2. Decomposition par phase : part du temps passee dans l'echange avec le
       KDC (etapes 1-2) et dans l'echange avec le service (etapes 3-5). Indique
       ou se depense le temps.

    3. Debit soutenu : nombre d'authentifications completes par seconde sur une
       duree donnee. Mesure la capacite de charge du KDC et du service.

Le script se connecte a un KDC et un service deja demarres (par docker-compose
ou par lancement local). Il lit la cle du client dans le fichier indique.

Usage :
    python mesures.py --cle /partage/client/K_C.key \\
        --kdc 127.0.0.1:9001 --service 127.0.0.1:9002 \\
        --echantillons 1000 --chauffe 50
"""

import argparse
import math
import socket
import sys
import time

sys.path.insert(0, "/app")

from protocole import crypto, cadrage, messages
from protocole.messages import SENS_C2S, SENS_S2C, ErreurProtocole


# --- Statistiques -----------------------------------------------------------

def statistiques(valeurs):
    """Retourne un dictionnaire de statistiques descriptives (en ms)."""
    if not valeurs:
        return None
    triees = sorted(valeurs)
    n = len(triees)

    def percentile(p):
        # Position par interpolation lineaire.
        if n == 1:
            return triees[0]
        rang = p / 100.0 * (n - 1)
        bas = int(math.floor(rang))
        haut = int(math.ceil(rang))
        if bas == haut:
            return triees[bas]
        poids = rang - bas
        return triees[bas] * (1 - poids) + triees[haut] * poids

    moyenne = sum(triees) / n
    variance = sum((x - moyenne) ** 2 for x in triees) / n
    return {
        "n": n,
        "min": triees[0],
        "mediane": percentile(50),
        "moyenne": moyenne,
        "ecart_type": math.sqrt(variance),
        "p95": percentile(95),
        "p99": percentile(99),
        "max": triees[-1],
    }


def afficher_stats(titre, stats):
    if stats is None:
        print("%s : aucune donnee." % titre)
        return
    print("%s (n=%d)" % (titre, stats["n"]))
    print("    min      %8.3f ms" % stats["min"])
    print("    mediane  %8.3f ms" % stats["mediane"])
    print("    moyenne  %8.3f ms" % stats["moyenne"])
    print("    ecart-type %6.3f ms" % stats["ecart_type"])
    print("    p95      %8.3f ms" % stats["p95"])
    print("    p99      %8.3f ms" % stats["p99"])
    print("    max      %8.3f ms" % stats["max"])


def histogramme(valeurs, largeur=50, classes=12):
    """Trace un histogramme texte simple de la distribution des latences."""
    if not valeurs:
        return
    bas, haut = min(valeurs), max(valeurs)
    if haut == bas:
        print("    (toutes les valeurs egales a %.3f ms)" % bas)
        return
    pas = (haut - bas) / classes
    compte = [0] * classes
    for v in valeurs:
        indice = min(int((v - bas) / pas), classes - 1)
        compte[indice] += 1
    maxi = max(compte)
    print("    Distribution des latences (ms) :")
    for i in range(classes):
        borne_bas = bas + i * pas
        borne_haut = borne_bas + pas
        barre = "#" * int(compte[i] / maxi * largeur) if maxi else ""
        print("    [%7.3f - %7.3f) %5d %s"
              % (borne_bas, borne_haut, compte[i], barre))


# --- Un echange instrumente -------------------------------------------------

def echange_chronometre(client, hote_kdc, port_kdc, hote_service, port_service):
    """Execute un echange complet en mesurant chaque phase.

    Retourne (total_ms, phase_kdc_ms, phase_service_ms). Reproduit la logique
    du client, mais en inserant des points de mesure entre les phases.
    """
    # Phase KDC (etapes 1-2).
    t0 = time.perf_counter()
    nonce_1 = crypto.generer_nonce_protocole()
    enveloppe, ticket = client._demander_ticket(hote_kdc, port_kdc, nonce_1)
    cle_session, id_service_recu, nonce_1_recu, _ = (
        messages.ouvrir_enveloppe_client(client.cle_client, enveloppe)
    )
    if nonce_1_recu != nonce_1:
        raise ErreurProtocole("Nonce_1 non confirme.")
    t1 = time.perf_counter()

    # Phase service (etapes 3-5).
    contexte_cs = SENS_C2S + b"|" + client.id_client + b"|" + client.id_service
    cle_cs = crypto.deriver_sous_cle(cle_session, contexte_cs)
    nonce_2 = crypto.generer_nonce_protocole()
    msg3 = messages.construire_msg3(ticket, cle_cs, client.id_client, nonce_2)
    type_message, champs = client._echanger(hote_service, port_service, msg3)
    if type_message != cadrage.MSG4:
        raise ErreurProtocole("Reponse du service inattendue.")
    contexte_sc = SENS_S2C + b"|" + client.id_client + b"|" + client.id_service
    cle_sc = crypto.deriver_sous_cle(cle_session, contexte_sc)
    nonce_recu, _ = messages.ouvrir_reponse(cle_sc, champs[cadrage.CHAMP_REPONSE])
    if nonce_recu != messages._incrementer(nonce_2):
        raise ErreurProtocole("N_2 + 1 non confirme.")
    t2 = time.perf_counter()

    return ((t2 - t0) * 1000.0, (t1 - t0) * 1000.0, (t2 - t1) * 1000.0)


# --- Programme principal ----------------------------------------------------

def charger_cle(chemin):
    with open(chemin, "r", encoding="utf-8") as fichier:
        return bytes.fromhex(fichier.read().strip())


def separer_hote_port(chaine):
    hote, port = chaine.rsplit(":", 1)
    return hote, int(port)


def principal():
    analyseur = argparse.ArgumentParser(description="Mesures du prototole.")
    analyseur.add_argument("--cle", required=True,
                           help="fichier de la cle maitresse du client")
    analyseur.add_argument("--kdc", default="127.0.0.1:9001",
                           help="hote:port du KDC")
    analyseur.add_argument("--service", default="127.0.0.1:9002",
                           help="hote:port du service")
    analyseur.add_argument("--id-client", default="client_A")
    analyseur.add_argument("--id-service", default="service_S")
    analyseur.add_argument("--echantillons", type=int, default=1000,
                           help="nombre d'echanges mesures (regime permanent)")
    analyseur.add_argument("--chauffe", type=int, default=50,
                           help="echanges de chauffe, exclus des statistiques")
    analyseur.add_argument("--duree-debit", type=float, default=10.0,
                           help="duree en secondes pour la mesure de debit")
    analyseur.add_argument("--histogramme", action="store_true",
                           help="afficher un histogramme des latences totales")
    args = analyseur.parse_args()

    from protocole.client import Client

    cle_client = charger_cle(args.cle)
    client = Client(
        args.id_client.encode("utf-8"),
        cle_client,
        args.id_service.encode("utf-8"),
    )
    hote_kdc, port_kdc = separer_hote_port(args.kdc)
    hote_service, port_service = separer_hote_port(args.service)

    def un_echange():
        return echange_chronometre(
            client, hote_kdc, port_kdc, hote_service, port_service
        )

    # --- Phase de chauffe (mesuree a part) ---
    print("Chauffe : %d echanges..." % args.chauffe)
    latences_chauffe = []
    for _ in range(args.chauffe):
        total, _, _ = un_echange()
        latences_chauffe.append(total)
    if latences_chauffe:
        print("  latence de chauffe : moy %.3f ms, max %.3f ms"
              % (sum(latences_chauffe) / len(latences_chauffe),
                 max(latences_chauffe)))
    print()

    # --- Regime permanent : latence et decomposition ---
    print("Mesure : %d echanges..." % args.echantillons)
    totaux, phases_kdc, phases_service = [], [], []
    echecs = 0
    for _ in range(args.echantillons):
        try:
            total, pk, ps = un_echange()
            totaux.append(total)
            phases_kdc.append(pk)
            phases_service.append(ps)
        except ErreurProtocole:
            echecs += 1
    print("  echanges reussis : %d / %d (echecs : %d)"
          % (len(totaux), args.echantillons, echecs))
    print()

    print("=" * 56)
    print("1. LATENCE DE BOUT EN BOUT")
    print("=" * 56)
    afficher_stats("Echange complet", statistiques(totaux))
    if args.histogramme:
        histogramme(totaux)
    print()

    print("=" * 56)
    print("2. DECOMPOSITION PAR PHASE")
    print("=" * 56)
    afficher_stats("Phase KDC (etapes 1-2)", statistiques(phases_kdc))
    afficher_stats("Phase service (etapes 3-5)", statistiques(phases_service))
    if totaux:
        part_kdc = sum(phases_kdc) / sum(totaux) * 100
        part_service = sum(phases_service) / sum(totaux) * 100
        print("  Repartition moyenne : KDC %.1f %%, service %.1f %%"
              % (part_kdc, part_service))
    print()

    print("=" * 56)
    print("3. DEBIT SOUTENU")
    print("=" * 56)
    print("Mesure sur %.1f s..." % args.duree_debit)
    compte = 0
    echecs_debit = 0
    debut = time.perf_counter()
    while time.perf_counter() - debut < args.duree_debit:
        try:
            un_echange()
            compte += 1
        except ErreurProtocole:
            echecs_debit += 1
    ecoule = time.perf_counter() - debut
    print("  %d authentifications en %.2f s" % (compte, ecoule))
    print("  debit : %.1f authentifications / seconde" % (compte / ecoule))
    if echecs_debit:
        print("  echecs : %d" % echecs_debit)


if __name__ == "__main__":
    principal()
