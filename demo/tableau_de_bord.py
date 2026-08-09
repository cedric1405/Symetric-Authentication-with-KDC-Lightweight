"""Tableau de bord de visualisation en direct du protocole KDC.

Serveur HTTP local (bibliotheque standard uniquement) qui :
  - sert la page d'animation (tableau_de_bord.html) ;
  - diffuse en direct, via evenements envoyes par le serveur (SSE), les
    evenements de trace emis par les conteneurs KDC et service reellement en
    cours d'execution (docker compose logs -f) ;
  - permet de declencher, sur demande, un echange client unique ou une
    demonstration d'attaque par rejeu contre le deploiement reel.

Ne remplace ni la mesure de performance (mesures.py) ni les tests d'attaque
(tests_attaques.py) : ce tableau de bord est un outil de demonstration et de
pedagogie, branche sur le systeme reellement en cours d'execution.

Usage (le KDC et le service doivent deja tourner, par ex. via
`docker compose up -d kdc service`) :

    python demo/tableau_de_bord.py

Puis ouvrir http://127.0.0.1:8765 dans un navigateur.
"""

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RACINE_PROJET = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHEMIN_HTML = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "tableau_de_bord.html"
)
CHEMIN_ATTAQUE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "attaque_rejeu_direct.py"
)
CHEMIN_CLE_CLIENT = os.path.join(RACINE_PROJET, "partage", "client", "K_C.key")

HOTE = "127.0.0.1"
PORT = 8765

MOTIF_TRACE = re.compile(r"TRACE_JSON (\{.*\})")

_abonnes = []
_verrou_abonnes = threading.Lock()


def _diffuser(evenement):
    """Envoie un evenement a tous les navigateurs actuellement connectes."""
    with _verrou_abonnes:
        morts = []
        for f in _abonnes:
            try:
                f.put_nowait(evenement)
            except queue.Full:
                morts.append(f)
        for f in morts:
            _abonnes.remove(f)


def _suivre_flux(flux, source):
    """Lit un flux ligne a ligne et en extrait les evenements de trace JSON.

    Les lignes qui ne portent pas de trace sont diffusees telles quelles,
    comme evenement generique de type "log", pour rester visibles dans le
    tableau de bord (demarrage des conteneurs, messages d'erreur...).
    """
    for ligne in flux:
        ligne = ligne.rstrip("\n")
        if not ligne:
            continue
        correspondance = MOTIF_TRACE.search(ligne)
        if correspondance:
            try:
                evenement = json.loads(correspondance.group(1))
            except json.JSONDecodeError:
                continue
            _diffuser(evenement)
        else:
            _diffuser({"acteur": source, "evenement": "log", "texte": ligne})


def _suivre_logs_docker():
    """Suit en continu les journaux du KDC et du service deployes."""
    while True:
        try:
            processus = subprocess.Popen(
                ["docker", "compose", "logs", "-f", "--no-color",
                 "--no-log-prefix", "--tail=0", "kdc", "service"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, cwd=RACINE_PROJET,
            )
        except FileNotFoundError:
            _diffuser({"acteur": "systeme", "evenement": "log",
                       "texte": "docker introuvable ; impossible de suivre "
                                "les conteneurs."})
            return
        _suivre_flux(processus.stdout, "systeme")
        processus.wait()
        # Le flux s'est interrompu (conteneurs redemarres, docker relance...) :
        # on retente apres une courte pause plutot que d'abandonner.
        time.sleep(2.0)


def _lancer_echange_unique():
    _diffuser({"acteur": "systeme", "evenement": "log",
               "texte": "declenchement d'un echange client unique..."})
    try:
        processus = subprocess.Popen(
            ["docker", "compose", "run", "--rm",
             "-e", "CLIENT_REPETITIONS=1", "-e", "TRACE_JSON=1", "client"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=RACINE_PROJET,
        )
        _suivre_flux(processus.stdout, "client")
        processus.wait()
    except Exception as erreur:
        _diffuser({"acteur": "systeme", "evenement": "log",
                   "texte": "echec du declenchement : %s" % erreur})


def _lancer_attaque():
    _diffuser({"acteur": "systeme", "evenement": "log",
               "texte": "declenchement de la demonstration d'attaque par rejeu..."})
    if not os.path.exists(CHEMIN_CLE_CLIENT):
        _diffuser({"acteur": "systeme", "evenement": "log",
                   "texte": "cle client introuvable (%s) ; la phase 0 a-t-elle "
                            "ete executee ?" % CHEMIN_CLE_CLIENT})
        return
    try:
        env = dict(os.environ)
        env["TRACE_JSON"] = "1"
        processus = subprocess.Popen(
            [sys.executable, CHEMIN_ATTAQUE, "--cle", CHEMIN_CLE_CLIENT,
             "--kdc", "127.0.0.1:9001", "--service", "127.0.0.1:9002"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=RACINE_PROJET, env=env,
        )
        _suivre_flux(processus.stdout, "attaquant")
        processus.wait()
    except Exception as erreur:
        _diffuser({"acteur": "systeme", "evenement": "log",
                   "texte": "echec de la demonstration : %s" % erreur})


class Gestionnaire(BaseHTTPRequestHandler):
    def log_message(self, format_, *args):
        pass  # journal HTTP par defaut desactive (bruit inutile)

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True  # deconnexion attendue (onglet ferme,
            # reconnexion automatique du flux d'evenements...) : pas une erreur.

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._servir_fichier(CHEMIN_HTML, "text/html; charset=utf-8")
        elif self.path == "/evenements":
            self._servir_evenements()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/declencher/echange":
            threading.Thread(target=_lancer_echange_unique, daemon=True).start()
            self._accepte()
        elif self.path == "/declencher/attaque":
            threading.Thread(target=_lancer_attaque, daemon=True).start()
            self._accepte()
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def _accepte(self):
        self.send_response(202)
        self._cors()
        self.end_headers()

    def _servir_fichier(self, chemin, type_contenu):
        try:
            with open(chemin, "rb") as fichier:
                contenu = fichier.read()
        except FileNotFoundError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", type_contenu)
        self.send_header("Content-Length", str(len(contenu)))
        self._cors()
        self.end_headers()
        self.wfile.write(contenu)

    def _servir_evenements(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._cors()
        self.end_headers()
        f = queue.Queue(maxsize=2000)
        with _verrou_abonnes:
            _abonnes.append(f)
        try:
            while True:
                evenement = f.get()
                donnees = "data: %s\n\n" % json.dumps(
                    evenement, ensure_ascii=False
                )
                self.wfile.write(donnees.encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _verrou_abonnes:
                if f in _abonnes:
                    _abonnes.remove(f)


def principal():
    threading.Thread(target=_suivre_logs_docker, daemon=True).start()
    serveur = ThreadingHTTPServer((HOTE, PORT), Gestionnaire)
    print("Tableau de bord sur http://%s:%d" % (HOTE, PORT))
    print("(le KDC et le service doivent deja tourner : "
          "docker compose up -d kdc service)")
    try:
        serveur.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        serveur.shutdown()


if __name__ == "__main__":
    principal()
