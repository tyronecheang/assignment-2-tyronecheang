const Joi = require("joi");

const express = require('express');

const port = process.env.PORT || 3000;

const app = express();

app.use(express.urlencoded({ extended: true }));

app.get('/', (req,res) => {
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

app.get('/signup', (req,res) => {
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

app.get('/login', (req,res) => {
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

app.post('/signupSubmit', (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const usernameSchema = Joi.object(
		{
			username: Joi.string().alphanum().required()
		});
    
    const emailSchema = Joi.object(
        {
            email: Joi.string().email().required()
        });

    const passwordSchema = Joi.object(
        {
            password: Joi.string().required()
        });
    const usernameValidationResult = usernameSchema.validate({username});
    const emailValidationResult = emailSchema.validate({email});
    const passwordValidationResult = passwordSchema.validate({password});
    var errorMessage = 'The following fields are required:<ul>';
    if(usernameValidationResult.error != null) {
        errorMessage += '<li>Username</li>';
    }
    if(emailValidationResult.error != null) {
        errorMessage += '<li>Email</li>';
    }
    if(passwordValidationResult.error != null) {
        errorMessage += '<li>Password</li>';
    }
    if(usernameValidationResult.error == null && emailValidationResult.error == null && passwordValidationResult.error == null) {
        res.redirect("/members");
        return;
    } else {
        errorMessage += '</ul><a href="/signup">Try Again</a>'
        res.send(errorMessage);
    }
});

app.post('/loginSubmit', (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    const emailSchema = Joi.object(
        {
            email: Joi.string().email().required()
        });

    const passwordSchema = Joi.object(
        {
            password: Joi.string().required()
        });

    const emailValidationResult = emailSchema.validate({email});
    const passwordValidationResult = passwordSchema.validate({password});
    var errorMessage = 'The following fields are required:<ul>';
    if(emailValidationResult.error != null) {
        errorMessage += '<li>Email</li>';
    }
    if(passwordValidationResult.error != null) {
        errorMessage += '<li>Password</li>';
    }
    if(usernameValidationResult.error == null && emailValidationResult.error == null && passwordValidationResult.error == null) {
        res.redirect("/members");
        return;
    } else {
        errorMessage += '</ul><a href="/login">Try Again</a>'
        res.send(errorMessage);
    }
});

app.get('/members', (req,res) => {
    var html = `
    members page
    `;
    res.send(html);
});

app.listen(port, () => {
	console.log("Node application listening on port " + port);
}); 