"""
Module de cadrage TLV du prototole.

TCP transporte un flux d'octets sans frontieres de message : deux envois
peuvent arriver colles, un envoi peut arriver fragmente. Ce module fournit le
cadrage qui reconstitue des messages nets a partir de ce flux, sur deux
niveaux emboites.

Niveau exterieur (enveloppe de message) :
    [ type_message (1 octet) | longueur_totale (2 octets) | corps ]
    Le type_message identifie MSG1, MSG2, etc. La longueur_totale annonce la
    taille du corps, ce qui permet au receveur de lire exactement le bon
    nombre d'octets avant d'interpreter le message.

Niveau interieur (champs TLV) :
    Le corps est une suite de champs, chacun de la forme
    [ type_champ (1 octet) | longueur (2 octets) | valeur ].
    Les valeurs sont des octets bruts (identites, nonces, horodatages,
    chiffres).

Toutes les longueurs sont codees en big-endian (ordre reseau). Le module ne
fait aucune cryptographie : il ne connait que des octets.
"""

import struct


# --- Parametres de format ---------------------------------------------------

# Un octet pour le type (message ou champ) : 256 valeurs possibles, largement
# suffisant. Deux octets pour toute longueur : plafond de 65 535 octets, tres
# au-dessus des quelques centaines d'octets d'un message du protocole.
TAILLE_TYPE = 1
TAILLE_LONGUEUR = 2
TAILLE_MAX_VALEUR = 65535

# En-tete d'enveloppe : type_message (1) + longueur_totale (2) = 3 octets.
TAILLE_ENTETE_MESSAGE = TAILLE_TYPE + TAILLE_LONGUEUR

# Borne de securite : un corps de message ne peut exceder cette taille. Un
# en-tete annoncant davantage est rejete avant toute lecture, ce qui interdit
# a un adversaire de forcer l'attente ou l'allocation de donnees demesurees.
TAILLE_MAX_MESSAGE = 65535


# --- Types de messages (niveau exterieur) -----------------------------------

MSG1 = 0x01  # C -> KDC  : demande de cle de session
MSG2 = 0x02  # KDC -> C  : enveloppe client + ticket service
MSG3 = 0x03  # C -> S    : ticket + authentifiant
MSG4 = 0x04  # S -> C    : reponse d'authentification mutuelle


# --- Types de champs (niveau interieur) -------------------------------------

CHAMP_ID_CLIENT = 0x10
CHAMP_ID_SERVICE = 0x11
CHAMP_NONCE = 0x12
CHAMP_HORODATAGE = 0x13
CHAMP_ENVELOPPE_CLIENT = 0x20  # chiffre destine au client (sous K_C)
CHAMP_TICKET = 0x21            # chiffre destine au service (sous K_S)
CHAMP_AUTHENTIFIANT = 0x22     # chiffre de l'authentifiant (sous K_CS)
CHAMP_REPONSE = 0x23           # chiffre de la reponse du service (sous K_SC)


class ErreurCadrage(Exception):
    """Signale un message ou un champ mal forme."""


# --- Encodage / decodage d'un champ TLV -------------------------------------

def encoder_champ(type_champ, valeur):
    """Encode un champ unique au format [type | longueur | valeur].

    Retourne les octets du champ. La longueur de la valeur est verifiee pour
    tenir dans les deux octets reserves.
    """
    if len(valeur) > TAILLE_MAX_VALEUR:
        raise ErreurCadrage(
            "Valeur trop longue pour un champ : %d octets (max %d)."
            % (len(valeur), TAILLE_MAX_VALEUR)
        )
    # struct : ">" impose le big-endian ; "B" un octet non signe (le type) ;
    # "H" deux octets non signes (la longueur).
    entete = struct.pack(">BH", type_champ, len(valeur))
    return entete + valeur


def encoder_message(type_message, champs):
    """Assemble un message complet a partir d'une liste de champs.

    Entrees :
        type_message : MSG1, MSG2, MSG3 ou MSG4
        champs       : liste de couples (type_champ, valeur)

    Sortie :
        les octets du message : en-tete d'enveloppe suivi du corps TLV, prets
        a etre emis sur le socket.
    """
    corps = b"".join(encoder_champ(t, v) for (t, v) in champs)
    if len(corps) > TAILLE_MAX_MESSAGE:
        raise ErreurCadrage(
            "Corps de message trop long : %d octets (max %d)."
            % (len(corps), TAILLE_MAX_MESSAGE)
        )
    entete = struct.pack(">BH", type_message, len(corps))
    return entete + corps


def decoder_corps(corps):
    """Decoupe le corps d'un message en champs TLV.

    Retourne un dictionnaire {type_champ: valeur}. Un type de champ presente
    deux fois provoque une erreur, aucun champ du protocole n'etant repete.
    Un champ dont la longueur annoncee deborde du corps est rejete : c'est la
    verification qui interdit un cadrage interne incoherent.
    """
    champs = {}
    position = 0
    fin = len(corps)
    while position < fin:
        if position + TAILLE_TYPE + TAILLE_LONGUEUR > fin:
            raise ErreurCadrage("En-tete de champ tronque.")
        type_champ, longueur = struct.unpack_from(">BH", corps, position)
        position += TAILLE_TYPE + TAILLE_LONGUEUR
        if position + longueur > fin:
            raise ErreurCadrage(
                "Champ 0x%02x : longueur annoncee (%d) deborde du corps."
                % (type_champ, longueur)
            )
        valeur = corps[position:position + longueur]
        position += longueur
        if type_champ in champs:
            raise ErreurCadrage(
                "Champ 0x%02x present plusieurs fois." % type_champ
            )
        champs[type_champ] = valeur
    return champs


# --- Lecture depuis un socket (cote reception) ------------------------------

def _lire_exactement(socket_connexion, nombre_octets):
    """Lit exactement nombre_octets sur le socket, en insistant.

    TCP peut livrer un message en plusieurs morceaux : une seule lecture ne
    suffit pas. Cette fonction boucle jusqu'a avoir rassemble tous les octets
    attendus, ou signale une erreur si la connexion se ferme avant.
    """
    morceaux = []
    recus = 0
    while recus < nombre_octets:
        morceau = socket_connexion.recv(nombre_octets - recus)
        if not morceau:
            raise ErreurCadrage(
                "Connexion fermee : %d octets recus sur %d attendus."
                % (recus, nombre_octets)
            )
        morceaux.append(morceau)
        recus += len(morceau)
    return b"".join(morceaux)


def recevoir_message(socket_connexion):
    """Lit un message complet depuis le socket et le decode.

    Retourne un couple (type_message, champs), ou champs est le dictionnaire
    {type_champ: valeur}. La lecture procede en deux temps : l'en-tete
    d'enveloppe d'abord, dont on tire la longueur du corps, puis le corps
    exactement. La longueur annoncee est bornee avant lecture, afin qu'un
    en-tete malveillant ne puisse pas provoquer une attente ou une allocation
    demesuree.
    """
    entete = _lire_exactement(socket_connexion, TAILLE_ENTETE_MESSAGE)
    type_message, longueur_corps = struct.unpack(">BH", entete)
    if longueur_corps > TAILLE_MAX_MESSAGE:
        raise ErreurCadrage(
            "Longueur de corps annoncee (%d) au-dela du maximum (%d)."
            % (longueur_corps, TAILLE_MAX_MESSAGE)
        )
    corps = _lire_exactement(socket_connexion, longueur_corps)
    champs = decoder_corps(corps)
    return type_message, champs


def envoyer_message(socket_connexion, type_message, champs):
    """Encode puis emet un message complet sur le socket."""
    donnees = encoder_message(type_message, champs)
    socket_connexion.sendall(donnees)
