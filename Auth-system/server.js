const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'your-secret-key', // Change to a strong secret in production
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true if using HTTPS
}));

// In-memory user store (replace with a database in production)
let users = [];

// Middleware to check if user is authenticated
function requireAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Middleware for role-based access (e.g., admin only)
function requireRole(role) {
  return (req, res, next) => {
    if (req.session.role === role) {
      next();
    } else {
      res.status(403).send('Access denied');
    }
  };
}

app.use(express.static('public'));




// Routes
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/public/register.html');
});

app.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ id: users.length + 1, username, email, password: hashedPassword, role: role || 'user' });
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = user.id;
    req.session.role = user.role;
    res.redirect('/dashboard');
  } else {
    res.send('Invalid credentials');
  }
});

// ... (rest of your server.js remains the same)

// Updated dashboard route
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/public/dashboard.html');
});

// ... (rest of your server.js remains the same)

app.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
  res.send('<h1>Admin Panel</h1><a href="/logout">Logout</a>');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});