# NL Production Control — Neville Hill TCC

Real-time shared Repair Shed Operations tool.

## Deploy to Railway

### 1. Push to GitHub
```
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR-USERNAME/nl-production-control.git
git push -u origin main
```

### 2. Set up Railway
1. Go to [railway.app](https://railway.app) and log in
2. Click **New Project** → **Deploy from GitHub Repo**
3. Select your `nl-production-control` repo
4. Railway will auto-detect Node.js and start deploying

### 3. Add PostgreSQL
1. In your Railway project, click **+ New** → **Database** → **PostgreSQL**
2. Railway automatically sets the `DATABASE_URL` environment variable
3. The server creates tables automatically on first start

### 4. Generate a public URL
1. Go to your service **Settings** → **Networking**
2. Click **Generate Domain** to get a public URL
3. Share that URL with your team — everyone sees the same live data

## How it works
- **Express** serves the frontend and API
- **PostgreSQL** stores all shift data and config
- **Socket.io** syncs changes in real-time across all connected browsers
- Everyone on the same URL shares the same shed, same handover notes, same everything
- Changes appear instantly on all screens
