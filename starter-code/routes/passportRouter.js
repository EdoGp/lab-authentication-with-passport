const express = require('express');
const ensureLogin = require('connect-ensure-login');
const bcrypt = require('bcrypt');
const passportRouter = express.Router();

const passport = require('passport');

const bcryptSalt = 10;
const User = require('../models/user');

passportRouter.get('/signup', (req, res, next) => {
	res.render('passport/signup');
});

passportRouter.post('/signup', (req, res, next) => {
	const username = req.body.username;
	const password = req.body.password;
	if (username === '' || password === '') {
		res.render('passport/signup', {
			message: 'Please fill username and password',
		});
	}

	User.findOne({ username })
		.then((user) => {
			if (user !== null) {
				return res.render('passport/signup', {
					message: 'Username already taken, please choose a different username',
				});
			}
			const salt = Number(bcrypt.genSalt(bcryptSalt));
			const hashPass = bcrypt.hashSync(password, salt);

			const newUser = new User({ username, password: hashPass });
			newUser.save((err) => {
				if (err) {
					return res.render('passport/signup', {
						mesage: 'Something went wrong saving the user',
					});
				} else {
					return res.redirect('/');
				}
			});
		})
		.catch((err) => {
			next(err);
		});
});

passportRouter.get('/login', (req, res, next) => {
	res.render('passport/login', { message: req.flash('error') });
});

passportRouter.post(
	'login',
	passport.authenticate('local', {
		successRedirect: '/',
		failureRedirect: 'passport/login',
		failureFlash: true,
		passReqToCallback: true,
	}),
);

passportRouter.get('/logout', (req, res, next) => {
	req.logout();
	res.redirect('/login');
});

passportRouter.get(
	'/private-page',
	ensureLogin.ensureLoggedIn(),
	(req, res) => {
		res.render('/passport/private', { user: req.user });
	},
);

module.exports = passportRouter;
