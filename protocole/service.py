"""
Le service (serveur applicatif).

Le service detient sa cle maitresse K_S, partagee avec le seul KDC. Il recoit
du client un MSG3 forme du ticket (scelle sous K_S par le KDC) et d'un
authentifiant (scelle sous K_CS par le client). Sa verification suit l'etape 4
de la conception :

    1. dechiffrer le ticket avec K_S  -> cle de session, id_client, expiration
    2. deriver K_CS a partir de l'identite lue DANS le ticket
    3. dechiffrer l'authentifiant avec K_CS
    4. verifier la concordance des identites, la fenetre temporelle, la
       validite du ticket, et la fraicheur du nonce N_2 (anti-rejeu)

Si tout est valide, le service derive K_SC et renvoie MSG4 (N_2 + 1), preuve
de son authenticite (etape 5).

Cache anti-rejeu : les nonces deja vus sont conserves en memoire vive. La
verification de fraicheur et l'enregistrement du nonce forment une operation
indivisible, protegee par un verrou : deux MSG3 concurrents portant le meme
nonce ne peuvent pas franchir simultanement un controle qui les examinerait
l'un apres l'autre. Cette indivisibilite conditionne la propriete anti-rejeu
elle-meme, elle n'est pas un simple detail de mise en oeuvre.
"""

import socket
import threading
import time

from . import crypto
from . import cadrage
from . import messages
from . import trace
from .messages import SENS_C2S, SENS_S2C


class CacheNonces:
    """Cache des nonces vus, avec verification-et-enregistrement atomique."""

    def __init__(self):
        self._vus = {}                 # nonce -> horodatage d'enregistrement
        self._verrou = threading.Lock()

    def verifier_et_enregistrer(self, nonce, maintenant=None):
        """Retourne True si le nonce est nouveau, et l'enregistre alors.

        Retourne False si le nonce a deja ete vu (tentative de rejeu). La
        verification et l'enregistrement se font sous verrou, de facon
        indivisible : c'est ce qui interdit a deux requetes concurrentes de
        passer toutes deux un controle sequentiel.
        """
        if maintenant is None:
            maintenant = int(time.time())
        with self._verrou:
            self._purger(maintenant)
            if nonce in self._vus:
                return False
            self._vus[nonce] = maintenant
            return True

    def _purger(self, maintenant):
        """Retire les nonces sortis de la fenetre de tolerance.

        Un nonce dont l'horodatage est hors fenetre serait de toute facon
        rejete a la verification temporelle ; le conserver est inutile. La
        taille du cache reste ainsi bornee par la duree de la fenetre.
        """
        limite = maintenant - messages.FENETRE_TOLERANCE
        expires = [n for n, t in self._vus.items() if t < limite]
        for n in expires:
            del self._vus[n]


class Service:
    """Serveur applicatif TCP verifiant l'authentification des clients."""

    def __init__(self, id_service, cle_service,
                 hote="127.0.0.1", port=9002):
        self.id_service = id_service
        self.cle_service = cle_service
        self.hote = hote
        self.port = port
        self.cache = CacheNonces()
        self._socket = None
        self._actif = False

    def demarrer(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.hote, self.port))
        self._socket.listen(8)
        self._actif = True
        while self._actif:
            try:
                connexion, _ = self._socket.accept()
            except OSError:
                break
            fil = threading.Thread(
                target=self._servir, args=(connexion,), daemon=True
            )
            fil.start()

    def arreter(self):
        self._actif = False
        if self._socket:
            self._socket.close()

    def _servir(self, connexion):
        """Traite un MSG3, renvoie MSG4 si l'authentification reussit."""
        try:
            type_message, champs = cadrage.recevoir_message(connexion)
            if type_message != cadrage.MSG3:
                return
            resultat = self.verifier(champs)
            if resultat is not None:
                connexion.sendall(resultat)
        except Exception:
            pass
        finally:
            connexion.close()

    def verifier(self, champs, maintenant=None):
        """Applique l'etape 4 et construit MSG4, ou retourne None si rejet.

        Isolee de la couche socket pour etre testable directement. Retourne
        les octets de MSG4 en cas de succes, None sinon.
        """
        if maintenant is None:
            maintenant = int(time.time())

        ticket = champs.get(cadrage.CHAMP_TICKET)
        authentifiant = champs.get(cadrage.CHAMP_AUTHENTIFIANT)
        if ticket is None or authentifiant is None:
            trace.emettre("service", "msg3_incomplet")
            return None
        trace.emettre("service", "msg3_recu")

        # 1. Ouvrir le ticket avec K_S. Une alteration fait echouer GCM.
        try:
            cle_session, id_client, expiration = messages.ouvrir_ticket(
                self.cle_service, ticket
            )
        except Exception:
            trace.emettre("service", "ticket_illisible")
            return None
        trace.emettre(
            "service", "ticket_ouvert",
            id_client=trace.texte_ou_none(id_client),
        )

        # Le ticket doit etre encore valide.
        if not messages.ticket_valide(expiration, maintenant):
            trace.emettre(
                "service", "ticket_expire",
                id_client=trace.texte_ou_none(id_client),
            )
            return None

        # 2. Deriver K_CS a partir de l'identite lue DANS le ticket, non de ce
        #    que l'expediteur pretend.
        contexte_cs = SENS_C2S + b"|" + id_client + b"|" + self.id_service
        cle_cs = crypto.deriver_sous_cle(cle_session, contexte_cs)

        # 3. Ouvrir l'authentifiant avec K_CS.
        try:
            id_auth, horodatage, nonce_2 = messages.ouvrir_authentifiant(
                cle_cs, authentifiant
            )
        except Exception:
            trace.emettre(
                "service", "authentifiant_illisible",
                id_client=trace.texte_ou_none(id_client),
            )
            return None

        # 4a. Concordance des identites du ticket et de l'authentifiant.
        if id_auth != id_client:
            trace.emettre(
                "service", "identites_incoherentes",
                id_ticket=trace.texte_ou_none(id_client),
                id_authentifiant=trace.texte_ou_none(id_auth),
            )
            return None

        # 4b. Fenetre temporelle de l'authentifiant.
        if not messages.horodatage_dans_fenetre(horodatage, maintenant):
            trace.emettre(
                "service", "horodatage_hors_fenetre",
                id_client=trace.texte_ou_none(id_client),
            )
            return None

        # 4c. Fraicheur du nonce : verification et enregistrement atomiques.
        #     L'ordre importe : on n'atteint ce point qu'apres avoir dechiffre
        #     ticket et authentifiant, donc un adversaire sans les cles ne peut
        #     pas remplir le cache de nonces arbitraires.
        if not self.cache.verifier_et_enregistrer(nonce_2, maintenant):
            trace.emettre(
                "service", "rejeu_detecte",
                id_client=trace.texte_ou_none(id_client),
            )
            return None  # nonce deja vu : rejeu

        # 5. Authentification mutuelle : deriver K_SC, renvoyer N_2 + 1.
        contexte_sc = SENS_S2C + b"|" + id_client + b"|" + self.id_service
        cle_sc = crypto.deriver_sous_cle(cle_session, contexte_sc)
        trace.emettre(
            "service", "msg4_envoye",
            id_client=trace.texte_ou_none(id_client),
        )
        return messages.construire_msg4(cle_sc, nonce_2)
