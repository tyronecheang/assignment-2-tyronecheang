require("./public/js/utils.js");

require('dotenv').config();

const session = require('express-session');
const express = require('express');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

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

function isAuthenticated(req, res, next) {
	if (req.session && req.session.authenticated) {
		next();
	} else {
		res.redirect('/login');
	}
}

async function isAdmin(req, res, next) {
	if (!req.session || !req.session.authenticated) {
		return res.redirect('/login');
	}

	const currentUser = await userCollection.findOne({ email: req.session.email });

	if (!currentUser || currentUser.type !== "admin") {
		res.status(403);
		return res.render("403");
	}

	next();
}

app.get('/', (req, res) => {
	res.render("landing", {
		authenticated: req.session.authenticated,
		username: req.session.username
	});
});

app.get('/signup', (req, res) => {
	if(req.session.authenticated) {
		return res.redirect("/members");
	}
	res.render("sign-up");
});

app.get('/login', (req, res) => {
	if(req.session.authenticated) {
		return res.redirect("/members");
	}
	res.render("login");
});

app.post('/signupSubmit', async (req, res) => {
	var username = req.body.username.trim();
	var email = req.body.email.trim().toLowerCase();
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

	var usernameError = usernameSchema.validate({ username }).error;
	var emailError = emailSchema.validate({ email }).error;
	var passwordError = passwordSchema.validate({ password }).error;

	if (usernameError || emailError || passwordError) {
		res.render("sign-up-error", {
			usernameError: usernameError,
			emailError: emailError,
			passwordError: passwordError
		});
	} else {
		var hashedPassword = await bcrypt.hash(password, saltRounds);

		const result = await userCollection.find({
			email: email
		}).project({
			username: 1,
			email: 1,
			password: 1,
			_id: 1
		}).toArray();

		if (result.length == 0) {
			await userCollection.insertOne({
				username: username,
				email: email,
				password: hashedPassword,
				type: "user"
			});
			req.session.username = username;
			req.session.email = email;
			req.session.authenticated = true;
			req.session.cookie.maxAge = expireTime;
			res.redirect("/members");
			return;
		} else {
			res.render("account-exists", { email: email });
		}
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

	if (result.length != 1) {
		res.render("user-not-found");
		return;
	}

	if (await bcrypt.compare(password, result[0].password)) {
		req.session.authenticated = true;
		req.session.email = email;
		req.session.username = result[0].username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/');
		return;
	} else {
		res.render("invalid-login");
		return;
	}
});

app.get('/members', isAuthenticated, (req, res) => {
	const images = ["bear-wave.gif", "poliwrath-wave.gif", "pikachu-wave.gif"];
	res.render("members", {
		username: req.session.username,
		images: images
	});
});

app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
	const users = await userCollection.find({}).toArray();
	res.render("user", {
		users: users,
		currentEmail: req.session.email
	});
});

app.post('/promote', isAuthenticated, isAdmin, async (req, res) => {
	const { email } = req.body;
	await userCollection.updateOne({ email: email }, { $set: { type: "admin" } });
	res.redirect('/admin');
});

app.post('/demote', isAuthenticated, isAdmin, async (req, res) => {
	const { email } = req.body;

	if (req.session.email === email) {
		res.send("You cannot demote yourself.");
		return;
	}

	await userCollection.updateOne({ email: email }, { $set: { type: "user" } });
	res.redirect('/admin');
});

app.get('/logout', (req, res) => {
	req.session.destroy();
	res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.get("*dummy", (req, res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port " + port);
});