"""
Le client.

Le client detient sa cle maitresse K_C, partagee avec le seul KDC. Pour
acceder a un service, il orchestre l'echange complet :

    - contacte le KDC (MSG1) et recoit MSG2 ;
    - ouvre son enveloppe avec K_C, en extrait la cle de session et le ticket ;
    - derive K_CS, forge l'authentifiant, envoie MSG3 au service ;
    - recoit MSG4, derive K_SC, verifie que la reponse vaut N_2 + 1.

La reussite de cette derniere verification etablit l'authentification mutuelle :
seul un service detenant la vraie cle de session a pu calculer N_2 + 1.
"""

import socket

from . import crypto
from . import cadrage
from . import messages
from . import trace
from .messages import SENS_C2S, SENS_S2C, ErreurProtocole


class Client:
    """Client orchestrant l'authentification aupres d'un service."""

    def __init__(self, id_client, cle_client, id_service):
        self.id_client = id_client
        self.cle_client = cle_client
        self.id_service = id_service

    def _echanger(self, hote, port, message):
        """Ouvre une connexion, envoie un message, lit la reponse eventuelle."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connexion:
            connexion.connect((hote, port))
            connexion.sendall(message)
            return cadrage.recevoir_message(connexion)

    def _demander_ticket(self, hote_kdc, port_kdc, nonce_1):
        """Etapes 1-2 : obtient enveloppe et ticket aupres du KDC."""
        msg1 = messages.construire_msg1(
            self.id_client, self.id_service, nonce_1
        )
        type_message, champs = self._echanger(hote_kdc, port_kdc, msg1)
        if type_message != cadrage.MSG2:
            raise ErreurProtocole("Reponse du KDC inattendue.")
        return (
            champs[cadrage.CHAMP_ENVELOPPE_CLIENT],
            champs[cadrage.CHAMP_TICKET],
        )

    def authentifier(self, hote_kdc, port_kdc, hote_service, port_service):
        """Deroule l'echange complet et retourne True si l'authentification
        mutuelle reussit.

        Leve ErreurProtocole en cas d'echec verifiable (nonce non confirme,
        reponse absente ou illisible).
        """
        # Etape 1-2 : obtenir le ticket aupres du KDC.
        nonce_1 = crypto.generer_nonce_protocole()
        trace.emettre(
            "client", "msg1_envoye",
            id_client=trace.texte_ou_none(self.id_client),
            id_service=trace.texte_ou_none(self.id_service),
        )
        enveloppe, ticket = self._demander_ticket(hote_kdc, port_kdc, nonce_1)
        trace.emettre("client", "msg2_recu")

        # Ouvrir l'enveloppe avec K_C.
        cle_session, id_service_recu, nonce_1_recu, _ = (
            messages.ouvrir_enveloppe_client(self.cle_client, enveloppe)
        )
        if nonce_1_recu != nonce_1:
            trace.emettre("client", "nonce1_invalide")
            raise ErreurProtocole(
                "Nonce_1 non confirme : reponse du KDC non fraiche."
            )
        if id_service_recu != self.id_service:
            trace.emettre("client", "service_inattendu")
            raise ErreurProtocole("Service annonce par le KDC inattendu.")

        # Etape 3 : deriver K_CS, forger l'authentifiant, envoyer MSG3.
        contexte_cs = SENS_C2S + b"|" + self.id_client + b"|" + self.id_service
        cle_cs = crypto.deriver_sous_cle(cle_session, contexte_cs)
        nonce_2 = crypto.generer_nonce_protocole()
        msg3 = messages.construire_msg3(
            ticket, cle_cs, self.id_client, nonce_2
        )
        trace.emettre("client", "msg3_envoye")

        type_message, champs = self._echanger(
            hote_service, port_service, msg3
        )
        if type_message != cadrage.MSG4:
            trace.emettre("client", "msg4_absent")
            raise ErreurProtocole("Reponse du service inattendue.")
        trace.emettre("client", "msg4_recu")

        # Etape 5 : deriver K_SC, verifier N_2 + 1.
        contexte_sc = SENS_S2C + b"|" + self.id_client + b"|" + self.id_service
        cle_sc = crypto.deriver_sous_cle(cle_session, contexte_sc)
        reponse = champs[cadrage.CHAMP_REPONSE]
        nonce_recu, _ = messages.ouvrir_reponse(cle_sc, reponse)

        attendu = messages._incrementer(nonce_2)
        if nonce_recu != attendu:
            trace.emettre("client", "authentification_echouee")
            raise ErreurProtocole(
                "Reponse du service invalide : N_2 + 1 non confirme."
            )
        trace.emettre("client", "authentification_reussie")
        return True
