# Contribuer à Take Ownership MAX

Merci de proposer des changements ciblés, testés et compatibles avec les versions de Windows prises en charge.

## Préparer une contribution

1. Créez une branche depuis `main`.
2. Limitez chaque proposition à un objectif clairement décrit.
3. Conservez la compatibilité Windows PowerShell 5.1, .NET Framework 4.x et C# 5.
4. N’ajoutez pas de dépendance externe sans justifier son besoin et son impact sur la distribution.
5. Ajoutez ou adaptez les tests pour chaque correction fonctionnelle ou de sécurité.

## Vérifications locales

Exécutez dans Windows PowerShell 5.1 :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-CLI.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Package.ps1
```

Une console administrateur est nécessaire pour les scénarios qui modifient réellement les propriétaires et DACL. Sans élévation, ces scénarios sont ignorés et le reste de la suite demeure exécutable.

## Principes à préserver

- aucune écriture d’ACL avant la sauvegarde durable et sa validation ;
- aucune traversée de lien symbolique, jonction ou redirection intermédiaire ;
- vérification de l’identité de chaque objet avant écriture ;
- restauration prudente en cas de changement concurrent ;
- absence de fermeture forcée des applications ;
- messages et rapports compréhensibles par un utilisateur francophone.

Pour une vulnérabilité non corrigée, utilisez la procédure privée de [SECURITY.md](SECURITY.md).
