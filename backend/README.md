# Backend Express MVC + MongoDB

## Installation

```bash
npm install
```

## Configuration

Create a `.env` file from `.env.example` and set your values.

## Run in development

```bash
npm run dev
```

## Run in production

```bash
npm start
```

## API Endpoints

- `GET /` : API health message
- `GET /api/patients` : List all patients
- `POST /api/patients` : Create patient

### POST example body

```json
{
  "fullName": "John Doe",
  "age": 32,
  "condition": "Stable"
}
```
