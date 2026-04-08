# PI Project - Frontend Angular + Backend Express MVC

Ce projet est compose de deux applications:
- `frontend`: application Angular (dashboard)
- `backend`: API Express.js avec architecture MVC et MongoDB (Mongoose)

## 1. Prerequis

Installe ces outils:
- Node.js LTS (version 20 conseillee)
- npm (fourni avec Node.js)
- MongoDB Atlas (cluster actif)
- Git

Verifie les versions:

```bash
node -v
npm -v
git --version
```

## 2. Structure du projet

```text
pi/
  frontend/        # Angular app
  backend/         # Express MVC API
```

Architecture backend MVC:
- `src/models`: schemas Mongoose
- `src/controllers`: logique metier HTTP
- `src/routes`: routes API
- `src/config`: configuration (connexion DB)
- `src/app.js`: configuration Express
- `src/server.js`: point d'entree serveur

## 3. Installation

Depuis la racine `pi`, installe les dependances dans chaque application:

```bash
cd frontend
npm install
cd ..
cd backend
npm install
cd ..
```

## 4. Configuration MongoDB (backend)

### 4.1 Creer le fichier .env

Dans `backend`, cree un fichier `.env` en copiant `.env.example`.

Exemple:

```env
PORT=5000
MONGO_URI=mongodb+srv://<db_username>:<db_password>@healthcaresoc.v84yxwe.mongodb.net/healthcare?retryWrites=true&w=majority&appName=healthcaresoc
```

### 4.2 Si ton username contient @

L'email doit etre URL-encode dans l'URI:
- `@` devient `%40`

Exemple username:
- `benterdayetalaa519@gmail.com` devient `benterdayetalaa519%40gmail.com`

### 4.3 Verifications Atlas

Si tu as `Authentication failed`:
- verifie le Database User (username/mot de passe exacts)
- verifie les droits de l'utilisateur sur la base
- autorise ton IP dans Network Access (ou 0.0.0.0/0 temporairement)

## 5. Lancer le backend

Dans un terminal:

```bash
cd backend
npm start
```

Notes:
- `npm start` utilise nodemon (redemarrage auto a chaque modification)
- API dispo sur `http://localhost:5000`

Endpoints de base:
- `GET /`
- `GET /api/patients`
- `POST /api/patients`

Exemple `POST /api/patients` body:

```json
{
  "fullName": "John Doe",
  "age": 32,
  "condition": "Stable"
}
```

## 6. Lancer le frontend

Dans un deuxieme terminal:

```bash
cd frontend
npm start
```

Application Angular dispo sur:
- `http://localhost:4200`

## 7. Lancer front + back en meme temps

Ouvre deux terminaux:

Terminal 1:

```bash
cd backend
npm start
```

Terminal 2:

```bash
cd frontend
npm start
```

## 8. Comment travailler sur le projet

### 8.1 Workflow recommande

1. Creer une branche:

```bash
git checkout -b feature/nom-fonctionnalite
```

2. Developper (front ou back)
3. Tester localement
4. Commit clair:

```bash
git add .
git commit -m "feat: ajout endpoint patients"
```

5. Push de la branche:

```bash
git push -u origin feature/nom-fonctionnalite
```

6. Ouvrir une Pull Request

### 8.2 Ajouter une nouvelle ressource backend (exemple: incidents)

1. Creer un model dans `backend/src/models`
2. Creer un controller dans `backend/src/controllers`
3. Creer une route dans `backend/src/routes`
4. Brancher la route dans `backend/src/app.js`
5. Tester avec Postman/Insomnia

### 8.3 Ajouter une page frontend

1. Creer la page dans `frontend/src/app/pages`
2. Ajouter la route dans `frontend/src/app/app.routes.ts`
3. Connecter le service API dans `frontend/src/app/core/services`
4. Tester l'affichage et les appels HTTP

## 9. Scripts utiles

Frontend (`frontend/package.json`):
- `npm start`: demarrer Angular
- `npm run build`: build production
- `npm test`: tests Angular

Backend (`backend/package.json`):
- `npm start`: demarrer API avec nodemon
- `npm run dev`: alias nodemon

## 10. Depannage rapide

### Backend ne demarre pas
- verifier `backend/.env`
- verifier le port libre (`5000`)
- verifier connexion Atlas et whitelist IP

### Frontend ne compile pas
- relancer `npm install` dans `frontend`
- verifier version Node.js (LTS)
- lire les erreurs TypeScript dans le terminal

### Port deja utilise
- changer `PORT` dans `backend/.env`
- lancer Angular sur un autre port:

```bash
cd frontend
npx ng serve --port 4201
```

## 11. Bonnes pratiques

- Ne jamais commit `backend/.env`
- Utiliser `.env.example` pour partager la structure
- Faire des commits petits et frequents
- Tester les endpoints apres chaque changement backend
- Garder les modeles, controllers et routes separes (MVC)
