"""
Module cryptographique du prototole.

Ce module encapsule les deux seules primitives cryptographiques utilisees
par le protocole : le chiffrement authentifie AES-256-GCM et la fonction de
derivation de cles HKDF. Il n'expose que leur interface d'usage (entrees,
sorties) et ne reimplemente aucun de leurs mecanismes internes, lesquels
relevent des standards qui les normalisent (NIST SP 800-38D pour GCM,
RFC 5869 pour HKDF). Le module ignore tout du protocole, des messages et du
reseau : il ne connait que des octets, des cles et des nonces.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# --- Parametres fixes du protocole -----------------------------------------

# Longueur des cles maitresses et de session : 256 bits = 32 octets.
LONGUEUR_CLE = 32

# Longueur du nonce (IV) d'AES-GCM : 96 bits = 12 octets, valeur recommandee
# par NIST SP 800-38D pour ce mode.
LONGUEUR_NONCE_GCM = 12


# --- Generation d'alea ------------------------------------------------------

def generer_cle():
    """Retourne une cle symetrique de 256 bits tiree aleatoirement.

    Utilisee par le KDC pour produire les cles maitresses (phase 0) et les
    cles de session (etape 2). L'alea provient de os.urandom, source
    cryptographiquement sure fournie par le systeme d'exploitation.
    """
    return os.urandom(LONGUEUR_CLE)


def generer_nonce_protocole(longueur=16):
    """Retourne un nonce de protocole (Nonce_1, N_2) tire aleatoirement.

    A distinguer du nonce d'AES-GCM : ce nonce-ci sert la logique anti-rejeu
    et defi-reponse du protocole, non le chiffrement lui-meme.
    """
    return os.urandom(longueur)


# --- Chiffrement authentifie AES-256-GCM ------------------------------------

def chiffrer(cle, message_clair, donnees_associees=None):
    """Chiffre et authentifie un message avec AES-256-GCM.

    Entrees :
        cle              : cle de 256 bits (32 octets)
        message_clair    : octets a chiffrer
        donnees_associees: octets authentifies mais non chiffres (AAD),
                           typiquement les etiquettes de type et de longueur
                           du cadre TLV ; peut etre None

    Sortie :
        nonce_gcm || chiffre, ou nonce_gcm (12 octets) est prepose au chiffre.
        Le chiffre inclut l'etiquette d'authentification GCM (16 octets).

    Le nonce GCM est tire aleatoirement a chaque appel et transmis en clair :
        sa confidentialite n'est pas requise, seule son unicite pour une cle
        donnee l'est, ce que l'alea garantit avec une probabilite ecrasante.
    """
    if len(cle) != LONGUEUR_CLE:
        raise ValueError(
            "Longueur de cle invalide : %d octets (attendu %d)."
            % (len(cle), LONGUEUR_CLE)
        )
    aesgcm = AESGCM(cle)
    nonce_gcm = os.urandom(LONGUEUR_NONCE_GCM)
    chiffre = aesgcm.encrypt(nonce_gcm, message_clair, donnees_associees)
    return nonce_gcm + chiffre


def dechiffrer(cle, donnees, donnees_associees=None):
    """Dechiffre et verifie un message produit par chiffrer().

    Entrees :
        cle              : cle de 256 bits (32 octets)
        donnees          : nonce_gcm || chiffre, tel que produit par chiffrer()
        donnees_associees: memes AAD que lors du chiffrement, sinon la
                           verification echoue

    Sortie :
        le message clair, si et seulement si l'etiquette d'authentification
        est valide.

    Leve une exception si la cle est mauvaise, si le message a ete altere, ou
    si les donnees associees ne correspondent pas : dans tous ces cas, GCM
    refuse de restituer le clair. C'est cette verification qui interdit la
    modification silencieuse d'un message en transit.
    """
    if len(cle) != LONGUEUR_CLE:
        raise ValueError(
            "Longueur de cle invalide : %d octets (attendu %d)."
            % (len(cle), LONGUEUR_CLE)
        )
    if len(donnees) < LONGUEUR_NONCE_GCM:
        raise ValueError("Donnees trop courtes pour contenir un nonce GCM.")
    aesgcm = AESGCM(cle)
    nonce_gcm = donnees[:LONGUEUR_NONCE_GCM]
    chiffre = donnees[LONGUEUR_NONCE_GCM:]
    # Leve cryptography.exceptions.InvalidTag si la verification echoue.
    return aesgcm.decrypt(nonce_gcm, chiffre, donnees_associees)


# --- Derivation de sous-cles HKDF -------------------------------------------

def deriver_sous_cle(cle_session, info):
    """Derive une sous-cle unidirectionnelle a partir de la cle de session.

    Entrees :
        cle_session : cle de session (secret racine, 256 bits)
        info        : octets de contexte liant la sous-cle a un usage precis.
                      Le protocole y place le sens de communication ("c2s" ou
                      "s2c") concatene aux identites du client et du service,
                      afin qu'une sous-cle ne puisse etre reutilisee hors de
                      la paire et du sens pour lesquels elle a ete derivee.

    Sortie :
        une sous-cle de 256 bits (K_CS ou K_SC selon le contexte).

    La cle de session n'est jamais employee directement pour chiffrer : elle
    ne sert que de secret racine a cette derivation, conformement a la
    conception (chapitre 4). Aucun sel n'est fourni, la cle de session etant
    deja une valeur aleatoire de pleine entropie.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=LONGUEUR_CLE,
        salt=None,
        info=info,
    )
    return hkdf.derive(cle_session)
