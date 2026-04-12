# Auth Server – TP1 à TP4

Serveur d'authentification REST sécurisé en Java avec Spring Boot.

## Stack technique
- Java 17
- Spring Boot 3.5.13
- Maven
- MySQL (production) / H2 (tests)
- Client : JavaFX

## Comment lancer MySQL et configurer application.properties
1. Installer MySQL
2. Créer une base de données : `CREATE DATABASE authdb;`
3. Modifier `application.properties` :
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/authdb
spring.datasource.username=sa
spring.datasource.password=
```

## Comment lancer l'API
```powershell
.\mvnw spring-boot:run
```

## Comment lancer le client Java
_À compléter_

## Compte de test
- Email : `toto@example.com`
- Mot de passe : `pwd1234`

## Analyse de sécurité TP1

### Risque 1 — Mot de passe stocké en clair
Le mot de passe est stocké tel quel dans la base de données.
Si un attaquant accède à la base, il obtient directement
tous les mots de passe sans aucun effort.

### Risque 2 — Mot de passe transmis en clair
Le mot de passe circule en clair dans la requête HTTP.
Sans HTTPS, n'importe qui sur le réseau peut le intercepter
et l'utiliser immédiatement.

### Risque 3 — Politique de mot de passe trop faible
Le minimum de 4 caractères permet des mots de passe
extrêmement simples comme "1234" ou "abcd", facilement
devinables par attaque par dictionnaire.

### Risque 4 — Pas de protection contre le brute force
Il n'y a aucune limite sur le nombre de tentatives de connexion.
Un attaquant peut essayer des milliers de mots de passe
automatiquement sans être bloqué.

### Risque 5 — Token basique non sécurisé
Le token est un simple UUID stocké en base sans expiration.
Si un attaquant vole ce token, il peut l'utiliser indéfiniment
sans aucune limite de temps.

## TP2 — Objectifs
- Politique de mot de passe stricte (12 caractères min, majuscule, minuscule, chiffre, caractère spécial)
- Hachage BCrypt des mots de passe
- Protection anti brute force (5 tentatives → blocage 2 minutes)
- SonarCloud obligatoire
- 10 tests JUnit minimum, 60% de couverture

## Qualité — TP2

### SonarCloud
- Quality Gate : Passed
- Couverture : 92%
- Duplications : 0.0%
- Vulnérabilités corrigées : logs utilisateur, regex DoS

### Comment SonarCloud est configuré
SonarCloud est configuré via le pom.xml avec les propriétés sonar.organization,
sonar.projectKey et sonar.host.url. L'analyse se lance avec :
```powershell
.\mvnw verify sonar:sonar -Dsonar.token=ffd7ef2cfc4828e27315f1446b52d1a6de79ef14
```

### Faiblesse de l'authentification TP2
Même avec BCrypt, le mot de passe est encore transmis directement
dans la requête de login. Si un attaquant capture la requête, il peut
tenter de la rejouer. TP3 corrigera cela avec HMAC et un nonce.

### Plan d'améliorations futures
- TP3 : Protocole HMAC + nonce anti-rejeu
- TP4 : Master Key AES-GCM + CI/CD GitHub Actions

## TP3 — Authentification Forte (HMAC)

### Protocole d'authentification
Le mot de passe ne circule plus sur le réseau.
Le client prouve qu'il connaît le secret sans l'envoyer.

#### Étape 1 — Le client calcule une preuve signée
- Génère un nonce (UUID aléatoire)
- Récupère le timestamp actuel (epoch secondes)
- Calcule : message = email + ":" + nonce + ":" + timestamp
- Calcule : hmac = HMAC_SHA256(clé = motDePasse, données = message)
- Envoie : { email, nonce, timestamp, hmac }

#### Étape 2 — Le serveur vérifie la preuve
1. Vérifie que l'email existe → sinon 401
2. Vérifie le timestamp dans une fenêtre de ±60 secondes → sinon 401
3. Vérifie que le nonce n'a pas déjà été utilisé → sinon 401
4. Enregistre le nonce en base
5. Déchiffre le mot de passe stocké
6. Recalcule le HMAC et compare en temps constant → sinon 401
7. Marque le nonce comme consommé
8. Retourne un accessToken valable 15 minutes

### Protections mises en place

| Mécanisme | Protège contre |
|-----------|---------------|
| HMAC-SHA256 | Interception du mot de passe |
| Timestamp ±60s | Requêtes trop anciennes |
| Nonce anti-rejeu | Réutilisation d'une requête capturée |
| Comparaison temps constant | Timing attacks |

### Structure base de données TP3
- Table `users` : id, email, password_encrypted, token, created_at
- Table `auth_nonce` : id, user_id, nonce, expires_at, consumed, created_at

### Résultats qualité TP3
- Quality Gate SonarCloud : Passed
- Couverture : 87.1%
- Duplications : 0.0%
- Tests : 24 — tous verts

## TP4 — Master Key + CI/CD

### Chiffrement AES-GCM
Les mots de passe sont chiffrés avec AES-GCM avant stockage en base.
La Master Key est injectée via variable d'environnement :
```powershell
$env:APP_MASTER_KEY="ta_master_key_secrete"
.\mvnw spring-boot:run
```

Ne jamais committer la Master Key dans le code !

### CI/CD GitHub Actions
La pipeline se déclenche automatiquement à chaque push :
- Build du projet
- Exécution des 29 tests JUnit
- Analyse SonarCloud
- Blocage si tests échouent ou Quality Gate rouge

### Résultats qualité TP4
- Quality Gate : Passed
- Couverture : 87%+
- Duplications : 0.0%
- Tests : 29 — tous verts

### Secrets GitHub configurés
- SONAR_TOKEN
- SONAR_PROJECT_KEY
- SONAR_ORGANIZATION

### Issues SonarCloud marquées Accepted
- PasswordPolicyValidator.java : expressions booléennes marquées redondantes
  par SonarCloud mais la logique est correcte et intentionnelle.
  Le break optimise la boucle et les vérifications finales sont nécessaires.

## TPs
- TP1 : Authentification dangereuse (mot de passe en clair) — tag v1-tp1
- TP2 : Authentification fragile (BCrypt + anti brute force) — tag v2-tp2
- TP3 : Authentification forte (HMAC + nonce) — tag v3-tp3
- TP4 : Master Key + CI/CD — tag v4-tp4
