# Prérégistration scientifique OASI — brouillon verrouillé avant mesure

Statut : `PREPARED_NOT_EXECUTED`

## Question

Le mécanisme OASI réduit-il les violations de sûreté one-shot et les effets
doublés sous crash/rejeu, comparé à des baselines fortes, à coût mesurable ?

## Baselines

- B0 : dispatch direct non persistant.
- B1 : transport authentifié stateless.
- B2 : ledger persistant at-least-once sans binding transactionnel complet.
- B3 : transaction locale conventionnelle idempotente avec clé de déduplication.
- OASI : broker borné + ledger atomique + binding génération/contexte + preuve
  de consommation.

## Hypothèses pré-enregistrées

- H1 sûreté : OASI produit zéro double effet sur les fautes définies.
- H2 reprise : OASI atteint un état terminal déterministe après crash/torn write.
- H3 sécurité : frames altérées, rejouées ou cross-generation sont rejetées.
- H4 coût : latence, CPU, mémoire et taille de ledger sont rapportés sans cacher
  les essais échoués.

## Métriques primaires

- taux de double effet;
- taux de replay accepté;
- proportion de runs terminalement récupérables;
- divergence A/B;
- latence p50/p95/p99 et débit, seulement après autorité performance;
- CPU, mémoire maximale et croissance ledger.

## Plan minimal

- graines déterministes publiées dans le paquet local;
- au moins 30 répétitions indépendantes par cellule pour l’estimation initiale;
- mêmes charges, mêmes fautes et même environnement pour toutes les baselines;
- intervalles de confiance à 95 %, tailles d’effet et données brutes conservées;
- aucune métrique ajoutée après observation sans la marquer exploratoire.

## Critères d’arrêt

- toute violation de sûreté OASI arrête la campagne et donne NO-GO;
- toute dérive de pin, réseau actif, résidu QEMU ou données manquantes invalide
  la cellule;
- aucune absence de différence ne doit être reformulée en supériorité.

## Frontière de claims

Ce document n’autorise pas la mesure de performance. Les PASS S1–S4 restent
locaux/fixtures ou boot-only; ils ne constituent pas une preuve d’avantage
scientifique, de sécurité de production ou de déploiement.

