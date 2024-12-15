const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = 3000;

const users = [];

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        connectSrc: ["'self'", "http://localhost:80"], // 80 port for front end
      },
    },
  })
);

app.use(cors({
  origin: 'http://localhost',  // localhost:80 
  credentials: true, 
}));

app.use(
  session({
    secret: 'Reznychenko',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      domain: 'localhost',  // domain front
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());


passport.use(
  new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    const user = users.find((u) => u.email === email);
    if (!user) {
      return done(null, false, { message: 'Incorrect email or password.' });
    }
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) return done(err);
      if (!isMatch) return done(null, false, { message: 'Incorrect email or password.' });
      return done(null, user);
    });
  })
);


passport.serializeUser((user, done) => {
  done(null, user.id);
});


passport.deserializeUser((id, done) => {
  const user = users.find((u) => u.id === id);
  done(null, user);
});


app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  const existingUser = users.find((u) => u.email === email);
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now().toString(), email, password: hashedPassword };
  users.push(newUser);
  res.status(201).json({ message: 'User registered successfully.' });
});


app.post('/login', passport.authenticate('local', {
  successRedirect: '/protected',
  failureRedirect: '/login-failed',
}));


app.post('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ message: 'Logout failed.' });
    res.status(200).json({ message: 'Logged out successfully.' });
  });
});


function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: 'Unauthorized' });
}

app.get('/protected', isAuthenticated, (req, res) => {
  res.status(200).json({ message: 'Welcome to the protected route!' });
});

app.get('/login-failed', isAuthenticated, (req, res) => {
  res.status(200).json({ message: 'Login fail!' });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
