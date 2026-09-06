# Politique de sécurité

## Versions prises en charge

La branche principale et la dernière version publiée de Take Ownership MAX v3 reçoivent les correctifs de sécurité.

## Signaler une vulnérabilité

N’ouvrez pas de ticket public pour une vulnérabilité non corrigée. Utilisez le formulaire privé [Signaler une vulnérabilité](https://github.com/Natixe/Take-Ownership-MAX/security/advisories/new).

Indiquez, si possible :

- la version ou le commit concerné ;
- la version et l’architecture de Windows ;
- les conditions nécessaires pour reproduire le problème ;
- l’impact observé ou attendu ;
- un exemple minimal ne contenant aucune donnée sensible.

Ne joignez pas de sauvegarde `backup.tomax`, de descripteur de sécurité complet ou de journal contenant des chemins privés. Un accusé de réception sera fourni dès que le rapport aura pu être examiné.

## Périmètre

Les contournements de confirmation, traversées de liens, remplacements de cible, écritures hors périmètre, élévations inattendues et altérations de sauvegarde sont considérés comme des problèmes de sécurité. Les limitations documentées concernant EFS, BitLocker, WDAC, AppLocker, les stratégies de groupe et les partages réseau ne constituent pas, à elles seules, des vulnérabilités du projet.
