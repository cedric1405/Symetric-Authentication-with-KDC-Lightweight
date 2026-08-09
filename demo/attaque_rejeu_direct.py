"""Demonstration en direct de l'attaque par rejeu (attaque 1 / attaque 7),
menee contre le deploiement conteneurise reellement en cours d'execution.

Contrairement a tests_attaques.py, qui isole la verification pour la rendre
testable, ce script se comporte comme un veritable adversaire reseau : il
obtient un MSG3 legitime aupres du KDC et du service deployes, l'envoie une
premiere fois (authentification normale), puis rejoue exactement les memes
octets. Sert a alimenter le tableau de bord de visualisation (demo/) avec une
attaque reelle sur le systeme reel, et non un scenario isole en memoire.

Usage :
    python demo/attaque_rejeu_direct.py --cle ./partage/client/K_C.key \\
        --kdc 127.0.0.1:9001 --service 127.0.0.1:9002
"""

import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocole import crypto, cadrage, messages, trace
from protocole.messages import SENS_C2S


def charger_cle(chemin):
    with open(chemin, "r", encoding="utf-8") as fichier:
        return bytes.fromhex(fichier.read().strip())


def separer_hote_port(chaine):
    hote, port = chaine.rsplit(":", 1)
    return hote, int(port)


def envoyer(hote, port, donnees):
    """Envoie des octets bruts sur une nouvelle connexion et lit la reponse."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connexion:
        connexion.connect((hote, port))
        connexion.sendall(donnees)
        try:
            return cadrage.recevoir_message(connexion)
        except Exception:
            return None


def principal():
    analyseur = argparse.ArgumentParser(
        description="Demonstration en direct de l'attaque par rejeu."
    )
    analyseur.add_argument("--cle", required=True,
                            help="fichier de la cle maitresse du client")
    analyseur.add_argument("--kdc", default="127.0.0.1:9001")
    analyseur.add_argument("--service", default="127.0.0.1:9002")
    analyseur.add_argument("--id-client", default="client_A")
    analyseur.add_argument("--id-service", default="service_S")
    args = analyseur.parse_args()

    from protocole.client import Client

    cle_client = charger_cle(args.cle)
    id_client = args.id_client.encode("utf-8")
    id_service = args.id_service.encode("utf-8")
    hote_kdc, port_kdc = separer_hote_port(args.kdc)
    hote_service, port_service = separer_hote_port(args.service)

    client = Client(id_client, cle_client, id_service)

    print("Obtention d'un MSG3 legitime aupres du deploiement reel...")
    trace.emettre("client", "msg1_envoye",
                   id_client=trace.texte_ou_none(id_client),
                   id_service=trace.texte_ou_none(id_service))
    nonce_1 = crypto.generer_nonce_protocole()
    enveloppe, ticket = client._demander_ticket(hote_kdc, port_kdc, nonce_1)
    trace.emettre("client", "msg2_recu")

    cle_session, _, _, _ = messages.ouvrir_enveloppe_client(
        cle_client, enveloppe
    )
    contexte_cs = SENS_C2S + b"|" + id_client + b"|" + id_service
    cle_cs = crypto.deriver_sous_cle(cle_session, contexte_cs)
    nonce_2 = crypto.generer_nonce_protocole()
    msg3 = messages.construire_msg3(ticket, cle_cs, id_client, nonce_2)
    trace.emettre("client", "msg3_envoye")

    print("Premier envoi (authentique)...")
    premier = envoyer(hote_service, port_service, msg3)
    if premier is not None and premier[0] == cadrage.MSG4:
        print("  MSG4 recu : authentification acceptee.")
    else:
        print("  echec inattendu du premier envoi.")

    print("Rejeu du meme MSG3, octet pour octet...")
    trace.emettre("attaquant", "rejeu_tente",
                   id_client=trace.texte_ou_none(id_client))
    rejeu = envoyer(hote_service, port_service, msg3)
    if rejeu is not None:
        trace.emettre("attaquant", "rejeu_accepte")
        print("  ACCEPTE : anomalie, le rejeu aurait du etre refuse.")
    else:
        trace.emettre("attaquant", "rejeu_refuse")
        print("  rejete par le service, comme attendu.")


if __name__ == "__main__":
    principal()
