"""
Module des messages du protocole.

Ce module traduit en code le flux en six etapes de la conception (chapitre 4).
Il assemble les deux briques de bas niveau, le chiffrement authentifie
(crypto) et le cadrage TLV (cadrage), pour construire et verifier les quatre
messages echanges :

    MSG1  C   -> KDC : { ID_C, ID_S, Nonce_1, T_1 }                 (en clair)
    MSG2  KDC -> C   : { enveloppe_client, ticket_service }         (chiffres)
    MSG3  C   -> S   : { ticket_service, authentifiant }            (chiffres)
    MSG4  S   -> C   : { reponse }                                  (chiffre)

Les contenus chiffres sont serialises en interne au format TLV : une enveloppe
n'est donc pas une simple concatenation, mais une structure dont chaque champ
est identifiable, ce qui interdit toute confusion entre deux valeurs de meme
longueur.

Liaison par donnees associees (AAD) : chaque chiffre est authentifie avec, en
donnees associees, le type du message et le sens de communication qui le
portent. Un adversaire ne peut donc ni transplanter un chiffre d'un message
vers un autre, ni inverser le sens client->service et service->client, sans
provoquer l'echec de la verification GCM.
"""

import struct
import time

from . import crypto
from . import cadrage


# --- Sens de communication, places en contexte HKDF et en AAD ---------------

SENS_C2S = b"c2s"  # client -> service
SENS_S2C = b"s2c"  # service -> client


# --- Fenetre temporelle -----------------------------------------------------

# Tolerance appliquee aux horodatages, en secondes (+/- 5 minutes).
FENETRE_TOLERANCE = 300

# Duree de validite d'un ticket, en secondes.
DUREE_TICKET = 300


class ErreurProtocole(Exception):
    """Signale un message du protocole invalide ou une verification echouee."""


# --- Serialisation interne des contenus chiffres ----------------------------
#
# Les valeurs internes d'une enveloppe (cle de session, identites, horodatages)
# sont elles-memes cadrees en TLV avant chiffrement, puis relues apres
# dechiffrement. On reutilise pour cela le module cadrage.

# Types de champs internes (distincts des types de champs de message).
_INT_CLE_SESSION = 0x30
_INT_ID_CLIENT = 0x31
_INT_ID_SERVICE = 0x32
_INT_NONCE = 0x33
_INT_HORODATAGE = 0x34
_INT_EXPIRATION = 0x35


def _empaqueter(champs):
    """Serialise une liste de champs internes (type, valeur) en octets TLV."""
    return b"".join(cadrage.encoder_champ(t, v) for (t, v) in champs)


def _depaqueter(donnees):
    """Relit des octets TLV internes en dictionnaire {type: valeur}."""
    return cadrage.decoder_corps(donnees)


def _horodatage_octets(valeur=None):
    """Code un horodatage (secondes depuis l'epoque) sur 8 octets big-endian."""
    if valeur is None:
        valeur = int(time.time())
    return struct.pack(">Q", valeur)


def _lire_horodatage(octets):
    """Relit un horodatage code sur 8 octets."""
    return struct.unpack(">Q", octets)[0]


def _aad(type_message, sens):
    """Construit les donnees associees liant un chiffre a son message et sens."""
    return struct.pack(">B", type_message) + sens


# --- Etape 1 : MSG1, C -> KDC (en clair) ------------------------------------

def construire_msg1(id_client, id_service, nonce_1):
    """Construit MSG1 : demande de cle de session, transmise en clair.

    Les identites circulent en clair car le KDC doit les lire pour selectionner
    les cles maitresses ; c'est le choix de conception qui exclut l'anonymat.
    """
    horodatage = _horodatage_octets()
    return cadrage.encoder_message(cadrage.MSG1, [
        (cadrage.CHAMP_ID_CLIENT, id_client),
        (cadrage.CHAMP_ID_SERVICE, id_service),
        (cadrage.CHAMP_NONCE, nonce_1),
        (cadrage.CHAMP_HORODATAGE, horodatage),
    ])


def lire_msg1(champs):
    """Extrait (id_client, id_service, nonce_1, horodatage) d'un MSG1 recu."""
    try:
        return (
            champs[cadrage.CHAMP_ID_CLIENT],
            champs[cadrage.CHAMP_ID_SERVICE],
            champs[cadrage.CHAMP_NONCE],
            _lire_horodatage(champs[cadrage.CHAMP_HORODATAGE]),
        )
    except KeyError as manquant:
        raise ErreurProtocole("MSG1 incomplet : champ %s absent." % manquant)


# --- Etape 2 : MSG2, KDC -> C -----------------------------------------------

def construire_msg2(cle_client, cle_service, cle_session,
                    id_client, id_service, nonce_1, expiration):
    """Construit MSG2 : deux enveloppes produites par le KDC.

    - enveloppe_client, chiffree sous K_C, porte la cle de session, l'identite
      du service, le nonce du client (pour qu'il verifie la fraicheur) et
      l'expiration.
    - ticket_service, chiffre sous K_S, porte la cle de session, l'identite du
      client et l'expiration. Le client ne peut pas l'ouvrir ; il le relaie.
    """
    contenu_client = _empaqueter([
        (_INT_CLE_SESSION, cle_session),
        (_INT_ID_SERVICE, id_service),
        (_INT_NONCE, nonce_1),
        (_INT_EXPIRATION, _horodatage_octets(expiration)),
    ])
    enveloppe_client = crypto.chiffrer(
        cle_client, contenu_client, _aad(cadrage.MSG2, SENS_S2C)
    )

    ticket = _construire_ticket(cle_service, cle_session, id_client, expiration)

    return cadrage.encoder_message(cadrage.MSG2, [
        (cadrage.CHAMP_ENVELOPPE_CLIENT, enveloppe_client),
        (cadrage.CHAMP_TICKET, ticket),
    ])


def _construire_ticket(cle_service, cle_session, id_client, expiration):
    """Chiffre le ticket destine au service, sous K_S."""
    contenu_ticket = _empaqueter([
        (_INT_CLE_SESSION, cle_session),
        (_INT_ID_CLIENT, id_client),
        (_INT_EXPIRATION, _horodatage_octets(expiration)),
    ])
    # Le ticket est authentifie comme provenant du KDC a destination du service.
    return crypto.chiffrer(
        cle_service, contenu_ticket, _aad(cadrage.MSG2, SENS_S2C)
    )


def ouvrir_enveloppe_client(cle_client, enveloppe):
    """Cote client : dechiffre l'enveloppe et en extrait le contenu.

    Retourne (cle_session, id_service, nonce_1, expiration). Une cle erronee
    ou une enveloppe alteree fait echouer le dechiffrement.
    """
    contenu = crypto.dechiffrer(
        cle_client, enveloppe, _aad(cadrage.MSG2, SENS_S2C)
    )
    champs = _depaqueter(contenu)
    return (
        champs[_INT_CLE_SESSION],
        champs[_INT_ID_SERVICE],
        champs[_INT_NONCE],
        _lire_horodatage(champs[_INT_EXPIRATION]),
    )


# --- Etape 3 : MSG3, C -> S -------------------------------------------------

def construire_msg3(ticket, cle_cs, id_client, nonce_2):
    """Construit MSG3 : le ticket relaye, plus l'authentifiant du client.

    L'authentifiant est chiffre sous K_CS (sens client->service) et porte
    l'identite du client, un horodatage frais et le nonce N_2 anti-rejeu.
    """
    contenu_auth = _empaqueter([
        (_INT_ID_CLIENT, id_client),
        (_INT_HORODATAGE, _horodatage_octets()),
        (_INT_NONCE, nonce_2),
    ])
    authentifiant = crypto.chiffrer(
        cle_cs, contenu_auth, _aad(cadrage.MSG3, SENS_C2S)
    )
    return cadrage.encoder_message(cadrage.MSG3, [
        (cadrage.CHAMP_TICKET, ticket),
        (cadrage.CHAMP_AUTHENTIFIANT, authentifiant),
    ])


def ouvrir_ticket(cle_service, ticket):
    """Cote service : dechiffre le ticket sous K_S.

    Retourne (cle_session, id_client, expiration).
    """
    contenu = crypto.dechiffrer(
        cle_service, ticket, _aad(cadrage.MSG2, SENS_S2C)
    )
    champs = _depaqueter(contenu)
    return (
        champs[_INT_CLE_SESSION],
        champs[_INT_ID_CLIENT],
        _lire_horodatage(champs[_INT_EXPIRATION]),
    )


def ouvrir_authentifiant(cle_cs, authentifiant):
    """Cote service : dechiffre l'authentifiant sous K_CS.

    Retourne (id_client, horodatage, nonce_2). La cle K_CS ayant ete derivee a
    partir de la cle de session extraite du ticket, seul un client detenant la
    vraie cle de session produit un authentifiant dechiffrable.
    """
    contenu = crypto.dechiffrer(
        cle_cs, authentifiant, _aad(cadrage.MSG3, SENS_C2S)
    )
    champs = _depaqueter(contenu)
    return (
        champs[_INT_ID_CLIENT],
        _lire_horodatage(champs[_INT_HORODATAGE]),
        champs[_INT_NONCE],
    )


# --- Etape 5 : MSG4, S -> C (authentification mutuelle) ---------------------

def construire_msg4(cle_sc, nonce_2, horodatage_octets=None):
    """Construit MSG4 : la reponse du service, preuve de son authenticite.

    Le service renvoie N_2 + 1 (et non N_2 tel quel) chiffre sous K_SC. Seul un
    detenteur de la vraie cle de session peut deriver K_SC et calculer cette
    valeur : un simple rejeu de l'authentifiant du client n'y suffit pas.
    """
    nonce_incremente = _incrementer(nonce_2)
    contenu = _empaqueter([
        (_INT_NONCE, nonce_incremente),
        (_INT_HORODATAGE, horodatage_octets or _horodatage_octets()),
    ])
    reponse = crypto.chiffrer(cle_sc, contenu, _aad(cadrage.MSG4, SENS_S2C))
    return cadrage.encoder_message(cadrage.MSG4, [
        (cadrage.CHAMP_REPONSE, reponse),
    ])


def ouvrir_reponse(cle_sc, reponse):
    """Cote client : dechiffre la reponse du service sous K_SC.

    Retourne (nonce_recu, horodatage). Le client verifie ensuite que
    nonce_recu vaut bien N_2 + 1.
    """
    contenu = crypto.dechiffrer(cle_sc, reponse, _aad(cadrage.MSG4, SENS_S2C))
    champs = _depaqueter(contenu)
    return (
        champs[_INT_NONCE],
        _lire_horodatage(champs[_INT_HORODATAGE]),
    )


def _incrementer(nonce):
    """Incremente de 1 un nonce vu comme un grand entier big-endian.

    Sert la logique defi-reponse de l'etape 5 : le service prouve qu'il detient
    la cle de session en renvoyant N_2 + 1, valeur qu'un rejeu ne peut fournir.
    """
    valeur = int.from_bytes(nonce, "big")
    valeur = (valeur + 1) % (1 << (len(nonce) * 8))
    return valeur.to_bytes(len(nonce), "big")


# --- Verifications temporelles partagees ------------------------------------

def horodatage_dans_fenetre(horodatage, maintenant=None):
    """Vrai si l'horodatage tombe dans la fenetre de tolerance autour de now."""
    if maintenant is None:
        maintenant = int(time.time())
    return abs(maintenant - horodatage) <= FENETRE_TOLERANCE


def ticket_valide(expiration, maintenant=None):
    """Vrai si le ticket n'a pas encore expire."""
    if maintenant is None:
        maintenant = int(time.time())
    return maintenant <= expiration
