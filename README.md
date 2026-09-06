# Take Ownership MAX

[![CI Windows](https://github.com/Natixe/Take-Ownership-MAX/actions/workflows/ci.yml/badge.svg)](https://github.com/Natixe/Take-Ownership-MAX/actions/workflows/ci.yml)
[![Licence MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

Take Ownership MAX est un utilitaire pour Windows 10 et Windows 11 qui répare les droits d’accès d’un fichier ou d’un dossier bloqué. Il peut reprendre le traitement après une interruption, restaurer les permissions d’origine et identifier les applications qui maintiennent un fichier ouvert.

> [!WARNING]
> Modifier des permissions NTFS est une opération sensible. Vérifiez toujours la cible affichée avant de confirmer et conservez le dossier de sauvegarde créé sous `%ProgramData%\TakeOwnershipMAX-Backups`.

## Fonctionnalités

| Action | Effet |
| --- | --- |
| **Réparer les accès** | Accorde le contrôle total au demandeur et au groupe Administrateurs, retire uniquement les refus qui les bloquent et conserve l’héritage existant. |
| **ULTIMATE** | Effectue la même réparation, convertit les règles héritées en règles explicites et protège la DACL contre de futurs changements hérités. |
| **Identifier les applications** | Interroge Windows Restart Manager pour afficher les processus qui utilisent un fichier. Une fermeture propre peut ensuite être demandée après confirmation. |
| **Restaurer** | Réapplique le propriétaire et la DACL enregistrés avant la réparation. |

Le moteur :

- sauvegarde chaque descripteur de sécurité avant la première écriture ;
- vérifie l’empreinte SHA-256 du journal avant toute modification ;
- refuse les jonctions, liens symboliques et redirections intermédiaires ;
- exclut par défaut les fichiers possédant plusieurs liens physiques ;
- détecte le remplacement d’un fichier entre l’inventaire et l’écriture ;
- relit chaque ACL après écriture et vérifie les droits effectifs avec l’API Windows Authz ;
- journalise les succès, exclusions, conflits et erreurs ;
- reprend une réparation ou une restauration interrompue.

## Prérequis

- Windows 10 ou Windows 11 ;
- volume NTFS ou ReFS ;
- Windows PowerShell 5.1 (`powershell.exe`) ;
- .NET Framework 4.x, inclus dans les versions prises en charge de Windows ;
- élévation administrateur pour modifier les permissions.

PowerShell 7 n’est pas utilisé : le moteur cible Windows PowerShell 5.1 et .NET Framework.

## Installation

1. Téléchargez `TakeOwnershipMAX-ULTIMATE-v3.zip` et son fichier `.sha256` depuis la page [Releases](https://github.com/Natixe/Take-Ownership-MAX/releases).
2. Vérifiez facultativement l’intégrité de l’archive :

   ```powershell
   $expected = (Get-Content .\TakeOwnershipMAX-ULTIMATE-v3.zip.sha256).Split()[0]
   $actual = (Get-FileHash .\TakeOwnershipMAX-ULTIMATE-v3.zip -Algorithm SHA256).Hash
   if ($actual -ne $expected) { throw 'Empreinte SHA-256 incorrecte.' }
   ```

3. Décompressez l’archive.
4. Lancez `Installer_Take_Ownership_MAX.cmd` et acceptez la demande UAC.

L’installation copie le moteur dans `%ProgramFiles%\TakeOwnershipMAX`, protège ce dossier contre les écritures non administratives et ajoute le menu contextuel de l’Explorateur.

## Utilisation depuis l’Explorateur

Sur un fichier, un dossier, l’arrière-plan d’un dossier ou un lecteur :

1. faites un clic droit ;
2. sous Windows 11, choisissez **Afficher plus d’options** ;
3. ouvrez **Take Ownership MAX ULTIMATE** ;
4. choisissez **Réparer les accès** ou **ULTIMATE**.

Sur un fichier ordinaire, l’action **Identifier les applications** indique les processus détectés par Restart Manager. La fermeture n’est jamais forcée : seuls les processus explicitement approuvés reçoivent une demande de fermeture propre. Les services, processus essentiels et le processus courant sont refusés.

## Ligne de commande

Ouvrez Windows PowerShell 5.1 dans le dossier décompressé.

### Réparer une cible

```powershell
.\Ressources\TakeOwnershipMAX.ps1 -TargetPath 'D:\Données' -Mode Repair
.\Ressources\TakeOwnershipMAX.ps1 -TargetPath 'D:\Données' -Mode Ultimate
```

Prévisualiser sans créer de sauvegarde ni modifier la cible :

```powershell
.\Ressources\TakeOwnershipMAX.ps1 -TargetPath 'D:\Données' -Mode Repair -WhatIf
```

### Reprendre ou restaurer

Le chemin d’opération est affiché au lancement et enregistré dans le rapport.

```powershell
.\Ressources\TakeOwnershipMAX.ps1 -Action Resume -OperationDirectory 'C:\ProgramData\TakeOwnershipMAX-Backups\OPERATION'
.\Ressources\TakeOwnershipMAX.ps1 -Action Restore -OperationDirectory 'C:\ProgramData\TakeOwnershipMAX-Backups\OPERATION'
```

Si les permissions ont changé depuis la réparation, la restauration s’arrête sur un conflit. Après vérification manuelle, `-OverwriteChanged` permet de confirmer l’écrasement de ces changements.

### Diagnostiquer un verrou

```powershell
.\Ressources\TakeOwnershipMAX.ps1 -Action Diagnose -TargetPath 'D:\Données\document.txt'
.\Ressources\TakeOwnershipMAX.ps1 -Action Diagnose -TargetPath 'D:\Données\document.txt' -CloseApplications
```

Enregistrez votre travail avant `-CloseApplications`. Les applications fermées ne sont pas relancées automatiquement.

### Options importantes

| Option | Description |
| --- | --- |
| `-Mode Repair` | Réparation conservant l’héritage. C’est le mode par défaut. |
| `-Mode Ultimate` | Réparation avec DACL protégée et héritage converti. |
| `-IncludeHardLinks` | Autorise explicitement les fichiers à liens physiques multiples. Leur ACL concerne tous leurs noms. |
| `-OverwriteChanged` | Autorise la restauration malgré un changement d’ACL intervenu après l’opération. |
| `-Force` | Supprime les confirmations interactives, y compris pour les emplacements sensibles. À réserver aux scripts contrôlés. |
| `-NoPause` | Ferme la console sans attendre une saisie finale. |

## Sauvegardes et rapports

Chaque opération possède un dossier privé contenant notamment :

| Fichier | Rôle |
| --- | --- |
| `state.json` | État durable, cible, mode et point de reprise. |
| `backup.tomax` | Sauvegarde binaire des propriétaires et DACL, dont l’intégrité est vérifiée par SHA-256. |
| `events.jsonl` | Journal détaillé et horodaté. |
| `report.json` | Résultat structuré exploitable par un script. |
| `rapport.txt` | Résumé lisible de l’opération. |

Ne supprimez pas `backup.tomax` tant qu’une restauration peut être nécessaire. Les sauvegardes sont conservées lors de la désinstallation.

## Codes de sortie

| Code | Signification |
| ---: | --- |
| `0` | Opération terminée et vérifiée, ou simulation `-WhatIf` acceptée. |
| `1` | Erreur ou paramètres invalides. |
| `2` | Résultat incomplet : échec, exclusion ou erreur d’inventaire. Une reprise est possible. |
| `3` | Élévation UAC annulée ou confirmation refusée. |

## Limites de sécurité

Take Ownership MAX répare le propriétaire et la DACL. Il ne :

- déchiffre pas EFS ou BitLocker et ne récupère aucune clé ;
- contourne pas WDAC, AppLocker, les stratégies de groupe ou les droits imposés par un serveur ;
- garantit pas qu’un fichier soit lisible si son contenu est chiffré, corrompu ou verrouillé ;
- suit pas les liens symboliques et jonctions ;
- tue pas les applications qui refusent une fermeture propre.

Sur un partage réseau, les règles et privilèges du serveur restent déterminants. Pour les emplacements Windows sensibles, une confirmation renforcée est demandée avant le traitement.

## Désinstallation

Lancez `Desinstaller_Take_Ownership_MAX.cmd` et acceptez la demande UAC. Le menu contextuel et le moteur installé sont supprimés ; les sauvegardes restent disponibles dans `%ProgramData%\TakeOwnershipMAX-Backups`.

## Architecture du dépôt

```text
.
├── .github/workflows/
│   ├── ci.yml
│   └── release.yml
├── Installer_Take_Ownership_MAX.cmd
├── Desinstaller_Take_Ownership_MAX.cmd
├── Build.ps1
├── CONTRIBUTING.md
├── SECURITY.md
├── Ressources/
│   ├── Install-Tomax.ps1
│   ├── TakeOwnershipMAX.ps1
│   └── Native/
│       ├── TomaxNative.cs
│       ├── TomaxEngine.cs
│       └── TomaxLocks.cs
└── tests/
    ├── Run-Tests.ps1
    ├── Test-CLI.ps1
    └── Test-Package.ps1
```

Le code C# reste compatible avec C# 5 afin d’être compilé par l’outillage .NET Framework fourni avec Windows. Aucun paquet externe n’est requis.

## Développement et tests

Depuis Windows PowerShell 5.1 :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-CLI.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Package.ps1
```

La suite standard teste la normalisation des chemins, les ACL, Authz, les journaux, les redirections, les liens physiques, les chemins longs et la reprise. Sans élévation, les scénarios qui écrivent des ACL privilégiées sont signalés comme ignorés. Exécutez la suite dans une console administrateur pour la couverture complète. Le test de charge est disponible avec :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1 -Stress
```

## Construire une archive

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1
```

Le dossier `dist/` reçoit l’archive prête à distribuer et son empreinte SHA-256. Les tags `v*` déclenchent le workflow de publication GitHub après validation des tests et du paquet.

## Contribution et sécurité

Consultez [CONTRIBUTING.md](CONTRIBUTING.md) avant de proposer une modification. Pour signaler une vulnérabilité, suivez la procédure privée décrite dans [SECURITY.md](SECURITY.md) plutôt que d’ouvrir un ticket public.

## Licence

Ce projet est distribué sous licence [MIT](LICENSE).
