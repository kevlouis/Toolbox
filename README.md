# Toolbox
Projet d'études de M1 : Toolbox automatiser 
# Toolbox 

 La Toolbox est un outil de test d'intrusion simple et intuitif conçu pour évaluer la sécurité des systèmes d'information. Il offre une interface graphique versatile pour effectuer diverses tâches de sécurité telles que le scan de ports, la détection de vulnérabilités, l'analyse de la sécurité des mots de passe, et bien plus encore.

## Fonctionnalités

- **Explorer les ports et les services** : Scanne les ports ouverts et identifie les services associés.
- **Détecter les vulnérabilités** : Analyse les services pour détecter des vulnérabilités connues.
- **Analyser la sécurité des mots de passe** : Évalue la robustesse des mots de passe.
- **Exécuter des tests d'authentification** : Vérifie les informations d'identification pour les connexions SSH.
- **Exploiter les vulnérabilités** : Tente d'exploiter les vulnérabilités identifiées pour accéder au système cible.
- **Analyse post-exploitation** : Effectue une analyse approfondie après l'exploitation pour identifier les données sensibles et les mesures de sécurité en place.

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

## Utilisation 

Une fois le raccourci créé, double-cliquez sur l'icône "Toolbox IT" sur votre bureau pour lancer l'interface graphique. Vous pouvez ensuite sélectionner les fonctionnalités que vous souhaitez utiliser et suivre les instructions à l'écran.

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

## Scripts
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
