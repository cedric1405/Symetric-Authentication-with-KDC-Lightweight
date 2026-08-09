"""
Le Centre de Distribution de Cles (KDC).

Le KDC est le tiers de confiance du protocole. Il detient une base associant
chaque identite a sa cle maitresse, generee lors de l'enregistrement (phase 0)
et distribuee hors bande. En fonctionnement, il repond aux demandes MSG1 des
clients : pour chaque paire (client, service) valide, il tire une cle de
session fraiche et renvoie MSG2, forme de l'enveloppe destinee au client et du
ticket destine au service.

Le KDC n'authentifie pas MSG1 : il ne peut pas, ne partageant avec le client
aucun secret verifiable avant l'echange. Un adversaire peut donc le solliciter,
mais n'obtient que des enveloppes scellees sous des cles maitresses qu'il ne
detient pas (cf. analyse de la disponibilite, chapitre 5).

Stockage de la base : fichier JSON en clair, protege par les permissions du
systeme de fichiers. Les cles maitresses, binaires, y sont encodees en
hexadecimal. Ce choix assume la concentration des secrets comme limite heritee
du modele centralise.
"""

import json
import os
import socket
import threading
import time

from . import crypto
from . import cadrage
from . import messages
from . import trace


class BaseDeCles:
    """Base associant chaque identite a sa cle maitresse, persistee en JSON."""

    def __init__(self, chemin):
        self.chemin = chemin
        self._cles = {}
        if os.path.exists(chemin):
            self._charger()

    def _charger(self):
        with open(self.chemin, "r", encoding="utf-8") as fichier:
            brut = json.load(fichier)
        # Les cles sont stockees en hexadecimal ; on les reconvertit en octets.
        self._cles = {
            identite: bytes.fromhex(cle_hex)
            for identite, cle_hex in brut.items()
        }

    def _sauver(self):
        brut = {
            identite: cle.hex() for identite, cle in self._cles.items()
        }
        # Ecriture avec permissions restreintes au seul proprietaire (0600).
        descripteur = os.open(
            self.chemin,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(descripteur, "w", encoding="utf-8") as fichier:
            json.dump(brut, fichier, indent=2)

    def enregistrer(self, identite):
        """Genere et stocke une cle maitresse pour une identite (phase 0).

        Retourne la cle generee, afin qu'elle soit distribuee hors bande a
        l'entite concernee.
        """
        cle = crypto.generer_cle()
        self._cles[identite] = cle
        self._sauver()
        return cle

    def cle_de(self, identite):
        """Retourne la cle maitresse d'une identite, ou None si inconnue."""
        return self._cles.get(identite)

    def contient(self, identite):
        return identite in self._cles


class KDC:
    """Service TCP repondant aux demandes de cle de session."""

    def __init__(self, base, hote="127.0.0.1", port=9001):
        self.base = base
        self.hote = hote
        self.port = port
        self._socket = None
        self._actif = False

    def demarrer(self):
        """Ouvre le socket d'ecoute et sert les demandes en boucle."""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.hote, self.port))
        self._socket.listen(8)
        self._actif = True
        while self._actif:
            try:
                connexion, _ = self._socket.accept()
            except OSError:
                break  # socket ferme : arret demande
            fil = threading.Thread(
                target=self._servir_client, args=(connexion,), daemon=True
            )
            fil.start()

    def arreter(self):
        self._actif = False
        if self._socket:
            self._socket.close()

    def _servir_client(self, connexion):
        """Traite une demande MSG1 et renvoie MSG2, ou ferme sur erreur."""
        try:
            type_message, champs = cadrage.recevoir_message(connexion)
            if type_message != cadrage.MSG1:
                return  # message inattendu : on ignore
            id_client, id_service, nonce_1, _ = messages.lire_msg1(champs)
            trace.emettre(
                "kdc", "msg1_recu",
                id_client=trace.texte_ou_none(id_client),
                id_service=trace.texte_ou_none(id_service),
            )

            # Sur le reseau, les identites circulent en octets ; la base les
            # indexe par chaine. On convertit au passage de l'une a l'autre.
            cle_client = self.base.cle_de(id_client.decode("utf-8"))
            cle_service = self.base.cle_de(id_service.decode("utf-8"))
            if cle_client is None or cle_service is None:
                # Entite inconnue : aucune reponse exploitable a produire.
                trace.emettre(
                    "kdc", "identite_inconnue",
                    id_client=trace.texte_ou_none(id_client),
                    id_service=trace.texte_ou_none(id_service),
                )
                return

            cle_session = crypto.generer_cle()
            expiration = int(time.time()) + messages.DUREE_TICKET
            msg2 = messages.construire_msg2(
                cle_client, cle_service, cle_session,
                id_client, id_service, nonce_1, expiration,
            )
            connexion.sendall(msg2)
            trace.emettre(
                "kdc", "msg2_envoye",
                id_client=trace.texte_ou_none(id_client),
                id_service=trace.texte_ou_none(id_service),
            )
        except cadrage.ErreurCadrage as erreur:
            # Une connexion fermee sans rien envoyer (sondage de disponibilite
            # du client, par exemple) n'est pas un evenement du protocole : on
            # ne la trace pas, pour ne pas la confondre avec un message reel
            # malforme.
            if "0 octets recus" not in str(erreur):
                trace.emettre("kdc", "erreur", detail=str(erreur))
        except Exception as erreur:
            # Un message malforme ou une connexion rompue ne doit pas
            # interrompre le KDC : on abandonne silencieusement cette demande.
            trace.emettre("kdc", "erreur", detail=str(erreur))
        finally:
            connexion.close()
