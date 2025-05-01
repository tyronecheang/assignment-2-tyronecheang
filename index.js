require("./utils.js");

require('dotenv').config();

const session = require('express-session');
const express = require('express');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {
	database
} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({
	extended: true
}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({
	secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false,
	resave: true
}));

app.get('/', (req, res) => {
	var html = `
    <div style="display: flex; flex-direction: column;">
        <form action='/signup' method='get' style="margin: 0;">
            <button>Sign up</button>
        </form>
        <form action='/login' method='get' style="margin: 0;">
            <button>Log in</button>
        </form>
    </div>
    `;
	res.send(html);
});

app.get('/signup', (req, res) => {
	var html = `
    User Sign-Up:
        <form action='/signupSubmit' method='post'>
            <input name='username' type='text' placeholder='username'><br>
            <input name='email' type='text' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
        <button>Submit</button>
        </form>
    `;
	res.send(html);
});

app.get('/login', (req, res) => {
	var html = `
    User Login
        <form action='/loginSubmit' method='post'>
            <input name='email' type='text' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
        <button>Submit</button>
        </form>
    `;
	res.send(html);
});

app.post('/signupSubmit', async (req, res) => {
	var username = req.body.username;
	var email = req.body.email;
	var password = req.body.password;

	const usernameSchema = Joi.object({
		username: Joi.string().alphanum().required()
	});

	const emailSchema = Joi.object({
		email: Joi.string().email().required()
	});

	const passwordSchema = Joi.object({
		password: Joi.string().required()
	});
	var errorMessage = 'The following fields are required:<ul>';
	if (usernameSchema.validate({username}).error != null) {
		errorMessage += '<li>Username</li>';
	}
	if (emailSchema.validate({email}).error != null) {
		errorMessage += '<li>Email</li>';
	}
	if (passwordSchema.validate({password}).error != null) {
		errorMessage += '<li>Password</li>';
	}
	if (usernameSchema.validate({username}).error == null &&
        emailSchema.validate({email}).error == null &&
        passwordSchema.validate({password}).error == null) {
		var hashedPassword = await bcrypt.hash(password, saltRounds);

		await userCollection.insertOne({
			username: username,
			email: email,
			password: hashedPassword
		});
		req.session.username = username;
		req.session.email = email;
        req.session.authenticated = true;
        req.session.cookie.maxAge = expireTime;
		res.redirect("/members");
		return;
	} else {
		errorMessage += '</ul><a href="/signup">Try Again</a>'
		res.send(errorMessage);
	}
});

app.post('/loginSubmit', async (req, res) => {
	var email = req.body.email;
	var password = req.body.password;

	const result = await userCollection.find({
		email: email
	}).project({
		username: 1,
		email: 1,
		password: 1,
		_id: 1
	}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("User Not Found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("Correct Password");
		req.session.authenticated = true;
		req.session.email = email;
		req.session.username = result[0].username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	} else {
		console.log("Incorrect Password");
		res.redirect("/login");
		return;
	}
});

app.get('/members', (req, res) => {
	if (!req.session.authenticated) {
		return res.redirect('/');
	}
	const images = ["bear-wave.gif", "poliwrath-wave.gif", "pikachu-wave.gif"];
	const randomImage = images[Math.floor(Math.random() * images.length)]
	var html = `
    hello ${req.session.username} <br>
		<img src='/${randomImage}' style='width:250px;'>
        <form action='/logout' method='get'>
            <button type="submit">Sign Out</button>
        </form>
    `;
	res.send(html);
});

app.get('/logout', (req, res) => {
	req.session.destroy();
	res.redirect('/')
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port " + port);
});