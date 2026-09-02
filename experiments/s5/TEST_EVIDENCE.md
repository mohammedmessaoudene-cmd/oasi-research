# Preuves de test S5

- Préflight historique : `PASS_S5_PREFLIGHT pins=5 tests=red_green verifier=independent result=absent network=denied` (le champ machine `independent` désigne un vérificateur détaché, pas une équipe indépendante).
- Tests unitaires : `PASS 6/6` sous CPython 3.12.3 et WSL x86_64.
- Campagne : `CAMPAIGN_COMPLETE`, 1 200 runs, 40 cellules.
- Vérification détachée : `PASS`, zéro violation de sûreté OASI, zéro
  appel réseau.
- Test rouge/vert du vérificateur : mutant OASI `effect_count=2` rejeté avec
  `OASI safety violation`, code retour 1.
- Résultat : `MECHANISM_ADVANTAGE_NOT_ESTABLISHED_AGAINST_B3`.

Les tests n'ont créé aucun effet réel et n'ont pas exécuté QEMU, guest,
déploiement, Stage7 ou publication.
