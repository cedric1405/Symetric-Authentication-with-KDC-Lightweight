"""
Scenarios d'attaque du prototole.

Chaque test reproduit une attaque analysee au chapitre 5 et verifie que le
protocole s'y oppose comme prevu. Les tests operent au niveau du service
(methode verifier), qui concentre la logique de defense, sauf le rejeu reseau
qui passe par de vrais sockets pour etre fidele.

Correspondance avec les attaques Kerberos (Diaz Motero et al., 2021)
---------------------------------------------------------------------
Le memoire compare ce protocole a Kerberos via les attaques qu'ils recensent.
Seules certaines sont TRANSPOSABLES ici : celles dont la cible existe dans ce
protocole. Les autres visent un mecanisme absent par construction et ne sont
donc pas testables — leur absence de cible EST la defense, pas une omission.

    Attaque Kerberos          Transposable ?   Test               Pourquoi
    ------------------------  ---------------  -----------------  --------------------------------
    Golden Ticket             NON              --                 pas de TGT (deux phases, pas trois)
    Kerberoasting             NON              --                 cles maitresses aleatoires, jamais
                                                                   derivees d'un mot de passe
    Devinette de mot de passe NON              --                 idem : rien a deviner
    Silver Ticket             OUI              test_usurpation_   detenteur d'une cle maitresse valide
                                                interne (test 2)   forgeant un ticket sans K_S
    Pass-the-Ticket           OUI              test_pass_the_     vol + rejeu d'un ticket legitime,
                                                ticket (test 8)    sans le forger

Les tests 1, 6 et 7 (rejeu direct, concurrence, rejeu reseau) et test 8
partagent le meme ressort que Pass-the-Ticket (rejeu, pas forgerie) ; test 8
est celui qui l'etiquette explicitement comme tel et verifie la double ligne
de defense (cache de nonces, puis expiration du ticket).
"""

import os
import tempfile
import threading
import time

from protocole import crypto, cadrage, messages
from protocole.messages import SENS_C2S, SENS_S2C
from protocole.kdc import BaseDeCles, KDC
from protocole.service import Service
from protocole.client import Client


ok = 0
ko = 0


def verifie(nom, condition):
    global ok, ko
    if condition:
        print("  OK  ", nom)
        ok += 1
    else:
        print("  ECHEC", nom)
        ko += 1


def preparer():
    """Cree une base, un KDC en memoire et un service, et retourne le tout."""
    base_fichier = os.path.join(tempfile.mkdtemp(), "cles.json")
    base = BaseDeCles(base_fichier)
    cle_c = base.enregistrer("client_A")
    cle_s = base.enregistrer("service_S")
    service = Service(b"service_S", cle_s)
    return base, cle_c, cle_s, service


def fabriquer_msg3(base, id_client, id_service):
    """Produit un MSG3 legitime pour (id_client, id_service), hors reseau.

    Retourne (champs_msg3, nonce_2, cle_session) pour permettre aux tests de
    manipuler l'echange.
    """
    cle_c = base.cle_de(id_client.decode())
    cle_s = base.cle_de(id_service.decode())
    cle_session = crypto.generer_cle()
    expiration = int(time.time()) + messages.DUREE_TICKET
    ticket = messages._construire_ticket(
        cle_s, cle_session, id_client, expiration
    )
    contexte_cs = SENS_C2S + b"|" + id_client + b"|" + id_service
    cle_cs = crypto.deriver_sous_cle(cle_session, contexte_cs)
    nonce_2 = crypto.generer_nonce_protocole()
    msg3 = messages.construire_msg3(ticket, cle_cs, id_client, nonce_2)
    _, champs = cadrage.MSG3, cadrage.decoder_corps(msg3[3:])
    return champs, nonce_2, cle_session


# --- Attaque 1 : rejeu d'un MSG3 -------------------------------------------

def test_rejeu():
    print("--- Attaque 1 : rejeu d'un MSG3 capture ---")
    base, cle_c, cle_s, service = preparer()
    champs, nonce_2, _ = fabriquer_msg3(base, b"client_A", b"service_S")

    # Premiere presentation : doit reussir.
    premier = service.verifier(champs)
    verifie("premiere presentation acceptee", premier is not None)

    # Rejeu du meme MSG3 (meme nonce) : doit etre refuse.
    rejeu = service.verifier(champs)
    verifie("rejeu du meme nonce refuse", rejeu is None)


# --- Attaque 2 : usurpation par adversaire interne (capacite C6) ------------
#
# Analogue du Silver Ticket (Diaz Motero et al., 2021) : dans Kerberos, un
# Silver Ticket est un TGS forge par un adversaire qui possede la cle d'un
# SERVICE mais pas celle du KDC, pour se faire passer aupres de ce service
# pour n'importe quel client. Ici, l'adversaire est symetrique : il possede
# sa PROPRE cle maitresse (valide, obtenue legitimement) mais pas celle du
# service vise (K_S), et tente de forger un ticket sous sa propre cle en
# pretendant etre un autre client. Meme ressort : possession d'une cle
# maitresse valide, mais pas de celle qui protege la cible.

def test_usurpation_interne():
    print("--- Attaque 2 (analogue Silver Ticket) : "
          "usurpation par un client legitime (C6) ---")
    base = BaseDeCles(os.path.join(tempfile.mkdtemp(), "cles.json"))
    base.enregistrer("client_A")   # victime
    cle_z = base.enregistrer("client_Z")   # adversaire, legitime
    cle_s = base.enregistrer("service_S")
    service = Service(b"service_S", cle_s)

    # Z obtient legitimement un ticket, mais pour LUI-MEME (client_Z), car le
    # KDC scelle l'enveloppe sous la cle de l'identite demandee. Z tente
    # ensuite de se faire passer pour client_A aupres du service.
    cle_session = crypto.generer_cle()
    expiration = int(time.time()) + messages.DUREE_TICKET

    # Cas a : Z forge un ticket pretendant venir de client_A, mais il ne
    # possede pas K_S ; il chiffre donc avec sa propre cle. Le service, qui
    # ouvre avec K_S, echoue.
    faux_ticket = messages._construire_ticket(
        cle_z, cle_session, b"client_A", expiration
    )
    contexte_cs = SENS_C2S + b"|" + b"client_A" + b"|" + b"service_S"
    cle_cs = crypto.deriver_sous_cle(cle_session, contexte_cs)
    nonce_2 = crypto.generer_nonce_protocole()
    msg3 = messages.construire_msg3(faux_ticket, cle_cs, b"client_A", nonce_2)
    _, champs = cadrage.MSG3, cadrage.decoder_corps(msg3[3:])
    resultat = service.verifier(champs)
    verifie("ticket forge sous une mauvaise cle rejete", resultat is None)


# --- Attaque 3 : ticket expire ----------------------------------------------

def test_ticket_expire():
    print("--- Attaque 3 : ticket expire ---")
    base, cle_c, cle_s, service = preparer()
    champs, nonce_2, _ = fabriquer_msg3(base, b"client_A", b"service_S")

    # On evalue la verification a un instant posterieur a l'expiration.
    futur = int(time.time()) + messages.DUREE_TICKET + 10
    resultat = service.verifier(champs, maintenant=futur)
    verifie("ticket expire refuse", resultat is None)


# --- Attaque 4 : authentifiant altere ---------------------------------------

def test_authentifiant_altere():
    print("--- Attaque 4 : authentifiant altere ---")
    base, cle_c, cle_s, service = preparer()
    champs, nonce_2, _ = fabriquer_msg3(base, b"client_A", b"service_S")

    # On inverse un bit de l'authentifiant : GCM doit rejeter.
    auth = bytearray(champs[cadrage.CHAMP_AUTHENTIFIANT])
    auth[-1] ^= 0x01
    champs_altere = dict(champs)
    champs_altere[cadrage.CHAMP_AUTHENTIFIANT] = bytes(auth)
    resultat = service.verifier(champs_altere)
    verifie("authentifiant altere rejete", resultat is None)


# --- Attaque 5 : ticket altere ----------------------------------------------

def test_ticket_altere():
    print("--- Attaque 5 : ticket altere ---")
    base, cle_c, cle_s, service = preparer()
    champs, nonce_2, _ = fabriquer_msg3(base, b"client_A", b"service_S")

    ticket = bytearray(champs[cadrage.CHAMP_TICKET])
    ticket[-1] ^= 0x01
    champs_altere = dict(champs)
    champs_altere[cadrage.CHAMP_TICKET] = bytes(ticket)
    resultat = service.verifier(champs_altere)
    verifie("ticket altere rejete", resultat is None)


# --- Attaque 6 : concurrence sur le meme nonce ------------------------------

def test_concurrence():
    print("--- Attaque 6 : deux MSG3 concurrents, meme nonce ---")
    base, cle_c, cle_s, service = preparer()
    champs, nonce_2, _ = fabriquer_msg3(base, b"client_A", b"service_S")

    # Deux fils presentent simultanement le meme MSG3. La verification atomique
    # ne doit en accepter qu'un seul.
    resultats = []
    verrou_resultats = threading.Lock()

    def presenter():
        r = service.verifier(dict(champs))
        with verrou_resultats:
            resultats.append(r)

    barriere = threading.Barrier(2)

    def presenter_synchronise():
        barriere.wait()  # maximiser la simultaneite
        presenter()

    fils = [threading.Thread(target=presenter_synchronise) for _ in range(2)]
    for f in fils:
        f.start()
    for f in fils:
        f.join()

    acceptes = sum(1 for r in resultats if r is not None)
    verifie("exactement un des deux MSG3 concurrents accepte", acceptes == 1)


# --- Attaque 7 : rejeu reseau reel ------------------------------------------

def test_rejeu_reseau():
    print("--- Attaque 7 : rejeu sur sockets reels ---")
    base_fichier = os.path.join(tempfile.mkdtemp(), "cles.json")
    base = BaseDeCles(base_fichier)
    cle_c = base.enregistrer("client_A")
    cle_s = base.enregistrer("service_S")

    kdc = KDC(base, port=9201)
    service = Service(b"service_S", cle_s, port=9202)
    threading.Thread(target=kdc.demarrer, daemon=True).start()
    threading.Thread(target=service.demarrer, daemon=True).start()
    time.sleep(0.3)

    import socket

    # Un client legitime obtient un MSG3 complet, qu'on capture.
    client = Client(b"client_A", cle_c, b"service_S")
    nonce_1 = crypto.generer_nonce_protocole()
    enveloppe, ticket = client._demander_ticket("127.0.0.1", 9201, nonce_1)
    cle_session, _, _, _ = messages.ouvrir_enveloppe_client(cle_c, enveloppe)
    contexte_cs = SENS_C2S + b"|" + b"client_A" + b"|" + b"service_S"
    cle_cs = crypto.deriver_sous_cle(cle_session, contexte_cs)
    nonce_2 = crypto.generer_nonce_protocole()
    msg3 = messages.construire_msg3(ticket, cle_cs, b"client_A", nonce_2)

    def envoyer(donnees):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", 9202))
            s.sendall(donnees)
            try:
                return cadrage.recevoir_message(s)
            except Exception:
                return None

    premier = envoyer(msg3)
    verifie("premier envoi accepte (MSG4 recu)",
            premier is not None and premier[0] == cadrage.MSG4)
    rejeu = envoyer(msg3)  # exactement les memes octets
    verifie("rejeu reseau refuse (pas de MSG4)", rejeu is None)

    kdc.arreter()
    service.arreter()


# --- Attaque 8 : vol et rejeu d'un ticket legitime ---------------------------
#
# Analogue du Pass-the-Ticket (Diaz Motero et al., 2021) : l'adversaire ne
# FORGE rien (contrairement au Silver Ticket, test 2) ; il VOLE un ticket et
# son authentifiant deja emis pour un client legitime, en interceptant le
# MSG3 en transit, puis les rejoue tels quels pour s'authentifier a sa place.
#
# Deux lignes de defense INDEPENDANTES sont verifiees ici :
#   1. dans la fenetre de validite, le cache de nonces du service qui a servi
#      la premiere presentation detecte le rejeu (meme ressort que le test 1,
#      mais etiquete ici explicitement comme l'analogue Pass-the-Ticket) ;
#   2. meme un service qui n'a JAMAIS vu ce nonce (redemarre entre-temps, ou
#      simplement un cache purge) refuse le meme ticket vole une fois son
#      expiration T_exp depassee. Cette seconde ligne ne depend pas de l'etat
#      du cache : elle borne la fenetre d'exploitation d'un ticket vole meme
#      dans le pire cas ou le cache de nonces ne le protegerait plus.

def test_pass_the_ticket():
    print("--- Attaque 8 (analogue Pass-the-Ticket) : "
          "vol et rejeu d'un ticket legitime ---")
    base, cle_c, cle_s, service = preparer()
    champs, nonce_2, _ = fabriquer_msg3(base, b"client_A", b"service_S")

    # L'adversaire capture le MSG3 en transit et le presente une premiere
    # fois : accepte, exactement comme le ferait le client legitime.
    premier = service.verifier(champs)
    verifie("ticket vole : premiere presentation acceptee", premier is not None)

    # Rejeu immediat du meme ticket vole, aupres du MEME service : le cache
    # de nonces le refuse.
    rejeu_immediat = service.verifier(champs)
    verifie("rejeu immediat refuse par le cache de nonces",
            rejeu_immediat is None)

    # Rejeu tardif du meme ticket vole, aupres d'un service FRAIS qui n'a
    # jamais vu ce nonce (cache vide) : refuse quand meme, car son
    # expiration T_exp est depassee. Defense independante du cache.
    service_frais = Service(b"service_S", cle_s)
    futur = int(time.time()) + messages.DUREE_TICKET + 10
    rejeu_tardif = service_frais.verifier(champs, maintenant=futur)
    verifie("rejeu tardif refuse par l'expiration du ticket (cache vide)",
            rejeu_tardif is None)


if __name__ == "__main__":
    test_rejeu()
    test_usurpation_interne()
    test_ticket_expire()
    test_authentifiant_altere()
    test_ticket_altere()
    test_concurrence()
    test_rejeu_reseau()
    test_pass_the_ticket()
    print()
    print("Resultat global : %d reussis, %d echoues" % (ok, ko))
