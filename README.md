# Libas - Daily Outfit Planner 👔👗

A user-friendly web application that helps you plan daily outfits from your wardrobe.

## Features

### Wardrobe Management
- Add, edit, and delete clothing items with name, category, color, and brand
- Organize items into configurable categories
- Mark categories as "repeatable" (e.g., belts and accessories can repeat on consecutive days)

### Daily Outfit Generation
- Automatically generates a unique outfit each day based on your wardrobe
- Picks one item from each category that has active items
- Deterministic seeding means the same suggestion appears if you reload (until you shuffle)

### User Controls
- **Shuffle** - Don't like the suggestion? Get a different one
- **Pin Items** - Force specific items to appear in today's outfit
- **Exclude** - Permanently ban an outfit combination from future suggestions
- **Wear This** - Accept and save an outfit as today's worn look

### History & Data
- Full outfit history tracking (last 30 days)
- View and restore excluded outfits
- Dashboard stats showing wardrobe size, outfits worn, and exclusions
- All data persisted in SQLite — no external database needed

## Project Structure

```
libas/
├── app.py                  # Flask backend, SQLite database, outfit logic
├── templates/
│   ├── index.html          # Main app (HTML/CSS/JS)
│   └── login.html          # Login & registration page
├── requirements.txt        # Python dependencies
├── Procfile                # Deployment process file
├── wsgi.py                 # WSGI entry point (gitignored)
├── wardrobe.db             # SQLite database (gitignored, auto-created)
├── .gitignore
└── README.md
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/categories` | List all categories |
| POST | `/api/categories` | Add a category |
| PUT | `/api/categories/<id>` | Update a category |
| DELETE | `/api/categories/<id>` | Delete a category |
| GET | `/api/items` | List all active items |
| POST | `/api/items` | Add an item |
| PUT | `/api/items/<id>` | Update an item |
| DELETE | `/api/items/<id>` | Soft-delete an item |
| GET | `/api/outfit/today` | Get today's outfit |
| POST | `/api/outfit/regenerate` | Generate a new outfit |
| POST | `/api/outfit/accept` | Save outfit as worn |
| POST | `/api/outfit/exclude` | Permanently exclude an outfit |
| GET | `/api/outfit/excluded` | List excluded outfits |
| DELETE | `/api/outfit/excluded/<id>` | Restore an excluded outfit |
| GET/POST/DELETE | `/api/pins` | Manage pinned items |
| GET | `/api/history` | View outfit history |
| GET | `/api/stats` | Dashboard statistics |
