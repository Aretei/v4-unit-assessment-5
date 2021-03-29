require('dotenv').config();
const express = require('express'),
      userCtrl = require('./controllers/user'),
      postCtrl = require('./controllers/posts');
const massive = require('massive');
const { CONNECTION_STRING, SERVER_PORT, SESSION_SECTRET } = process.env


const app = express();

app.use(express.json());

app.use(session({
    secret: SESSION_SECTRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}))

massive ({
    connectionString: CONNECTION_STRING,
    ssl: {
        rejectUnauthorized: false
    }
})
.then (dbInstance => {
    app.set('db', dbInstance)
    app.listen(SERVER_PORT, () => console.log(`serve is running on ${SERVER_PORT} and the db is connected...atleast it should be`))
})

//Auth Endpoints
app.post('/api/auth/register', userCtrl.register);
app.post('/api/auth/login', userCtrl.login);
app.get('/api/auth/me', userCtrl.getUser);
app.post('/api/auth/logout', userCtrl.logout);

//Post Endpoints
app.get('/api/posts', postCtrl.readPosts);
app.post('/api/post', postCtrl.createPost);
app.get('/api/post/:id', postCtrl.readPost);
app.delete('/api/post/:id', postCtrl.deletePost)

// app.listen(4000, _ => console.log(`running on ${4000}`));