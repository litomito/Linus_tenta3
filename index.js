const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const multer = require('multer');
const path = require('path');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

const redirectToHomeWithError = (res, errorMessage) => {
  res.redirect(`/?error=${encodeURIComponent(errorMessage)}`);
};

const authenticateUser = async (req, res, next) => {
  if (req.session.userId) {
    try {
      const user = await prisma.user.findUnique({
        where: { id: req.session.userId },
      });

      if (user) {
        req.user = user;
        console.log('Authenticated user:', user);
        next();
      } else {
        console.log('User not found.');
        redirectToHomeWithError(res, 'User not found.');
      }
    } catch (error) {
      console.error('Error fetching user:', error);
      redirectToHomeWithError(res, 'Error fetching user.');
    }
  } else {
    console.log('User not authenticated.');
    redirectToHomeWithError(res, 'User not authenticated.');
  }
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public', 'img'));
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage: storage });

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
        role,
      },
    });

    req.session.userId = user.id;
    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    redirectToHomeWithError(res, 'Registration failed. Please try again.');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: { username },
    });

    if (user && (await bcrypt.compare(password, user.password))) {
      req.session.userId = user.id;
      res.redirect('/dashboard');
    } else {
      redirectToHomeWithError(res, 'Invalid username or password.');
    }
  } catch (error) {
    console.error(error);
    redirectToHomeWithError(res, 'Login failed. Please try again.');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/dashboard', authenticateUser, async (req, res) => {
  try {
    const blogPosts = await prisma.blogPost.findMany();
    res.render('dashboard', { user: req.user, blogPosts });
  } catch (error) {
    console.error(error);
    redirectToHomeWithError(res, 'Error fetching dashboard data.');
  }
});

app.get('/blog/:postId', authenticateUser, async (req, res) => {
  const { postId } = req.params;
  console.log('postId:', postId);

  try {
    const blogPost = await prisma.blogPost.findUnique({
      where: { id: parseInt(postId) },
      include: { user: { select: { username: true } } },
    });

    if (!blogPost) {
      res.redirect('/dashboard');
      return;
    }
    res.render('blog', { user: req.user, blogPost });
  } catch (error) {
    console.error(error);
    redirectToHomeWithError(res, 'Error fetching blog post.');
  }
});

app.get('/create-post', authenticateUser, (req, res) => {
  if (!req.session.userId) {
    redirectToHomeWithError(res, 'Unauthorized. Please login.');
    return;
  }

  const userRole = 'admin';
  if (userRole !== 'admin') {
    res.redirect('/dashboard');
    return;
  }
  res.render('createPost');
});

app.post('/create-post', authenticateUser, upload.single('image'), async (req, res) => {
  if (!req.session.userId) {
    redirectToHomeWithError(res, 'Unauthorized. Please login.');
    return;
  }

  const { title, description } = req.body;
  const image = req.file ? '/img/' + req.file.originalname : '/img/default.jpg';
  console.log('Received data:', { title, description, image });

  try {
    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
    });

    if (!user || user.role !== 'admin') {
      res.redirect('/dashboard');
      return;
    }

    await prisma.blogPost.create({
      data: {
        title: title,
        description: description,
        image,
        userId: user.id,
      },
    });

    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    redirectToHomeWithError(res, 'Error creating blog post.');
  }
});

app.post('/delete-post/:postId', authenticateUser, async (req, res) => {
  const { postId } = req.params;

  try {
    const blogPost = await prisma.blogPost.findUnique({
      where: { id: parseInt(postId) },
      include: { user: { select: { id: true } } },
    });

    if (!blogPost) {
      res.redirect('/dashboard');
      return;
    }

    if (req.user.role === 'admin' && blogPost.user.id === req.user.id) {
      await prisma.blogPost.delete({
        where: { id: parseInt(postId) },
      });

      res.redirect('/dashboard');
    } else {
      res.redirect(`/blog/${postId}`);
    }
  } catch (error) {
    console.error(error);
    redirectToHomeWithError(res, 'Error deleting blog post.');
  }
});

app.listen(3000, () => {
  console.log(`Server is running on port 3000`);
});
