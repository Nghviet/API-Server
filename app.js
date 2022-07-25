var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var app = express();


app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

var bcrypt = require('bcrypt')

var mongodb = require('mongodb')
var MongoClient = mongodb.MongoClient
var ObjectId = mongodb.ObjectId
var jwt = require('jsonwebtoken')
var crypto = require('crypto')
var path = require('path')
var fs = require('fs')

var privateKey = fs.readFileSync('jwt.key');
console.log(privateKey)

var publicKey = fs.readFileSync('jwt.pem');
console.log(publicKey)

var encryptStringWithRsaPublicKey = function(toEncrypt) {

	console.log(toEncrypt)

    var buffer = Buffer.from(toEncrypt);

    var encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString("base64");
};

const uri = "mongodb://" + process.env.MONGO_URI;
var db = null
var client = new MongoClient(uri, {useNewUrlParser: true, useUnifiedTopology: true})

client.connect(err => {
	console.log(err)
	if(err) return
	db = client.db('development')
	console.log("Connected")
})

app.get('/API/login/available', (req,res) => {
	res.send("Login gateway up")
})

app.post('/API/signup', (req,res) => {
	console.log(req.body)
	var username = req.body.username
	var password = req.body.password
	var email = req.body.email

	if(username == undefined || password == undefined || email == undefined || username == '' || password == '' || email == '') {
		res.sendStatus(400)
		return
	}

	if(db == null) {
		res.sendStatus(500)
		return
	}

	db.collection('user').find({
		$or: [
			{'username' : username},
			{'email' : email} 
		]
	}).toArray((err,result) => {
		if(err) {
			console.log(err)
			res.sendStatus(500)
			return
		}

		if(result.length != 0) {
			res.status(500).send("Available user!")
			return
		}

		bcrypt.hash(password, 12, (err,hash) => {
			if(err) {
				res.sendStatus(500)
				return
			}

			db.collection('user').insertOne({
				username : username,
				password : hash,
				email : email
			})
			.then(result => {
				res.sendStatus(200)
				return
			})
			.catch(err => {
				res.sendStatus(500)
				return
			})
		})
	})
})

app.post('/API/register', (req,res) => {
	console.log(req.body)
	var username = req.body.username
	var password = req.body.password

	var home_MAC = req.body.mac
	if(username == undefined || username == '' || password == undefined || password == '' || home_MAC == undefined || home_MAC == '') {
		res.sendStatus(400)
		return
	}

	db.collection('user').find({username : username}).toArray((err,result) => {
		console.log(result)
		if(result.length == 0) {
			res.sendStatus(404)
			return
		}

		var user = result[0]

		bcrypt.compare(password, result[0].password, (err,result) => {
			if(err) {
				res.sendStatus(500)
				return
			}
			
			if(result == false) {
				res.sendStatus(401)
				return
			}
			
			db.collection('home').find({'user_id' : ObjectId(user._id), 'mac_address' : home_MAC})
			.toArray((err,result) => {
				if(err) {
					res.sendStatus(500)
					return
				}

				if(result.length == 0) {
					db.collection('home').insertOne({
						user_id : ObjectId(user._id),
						mac_address : home_MAC
					}).then(result => {
						console.log(result)
						jwt.sign({
							user_id : encryptStringWithRsaPublicKey(user._id.toString()),
							home_id : encryptStringWithRsaPublicKey(result.insertedId.toString())
						}, privateKey, { algorithm: 'RS256'}, (err,token) => {
							if(err) {
								res.sendStatus(500)
								return
							}
							res.status(200).send(token)
						}) 
					}).catch(err => {
						console.log(err)
					})
				} else {
					jwt.sign({
						user_id : encryptStringWithRsaPublicKey(user._id.toString()),
						home_id : encryptStringWithRsaPublicKey(result[0]._id.toString())
					}, privateKey, { algorithm: 'RS256'}, (err,token) => {
						if(err) {
							res.sendStatus(500)
							return
						}
						res.status(200).send(token)
					})
				}
			})

		})
	})
})

app.post('/API/login', (req,res) => {

})

app.post('/API/house_online', (req,res) => {

})

app.get('/API/discrete', (req,res) => {
	let file = '/vietnh/model/discrete/' + req.headers.user_id + '-' + req.headers.home_id + '_discrete.csv'
	res.sendFile(file)
})

app.get('/API/device_pattern', (req,res) => {
	let file = '/vietnh/model/device_pattern/' + req.headers.user_id + '-' + req.headers.home_id + '_device.csv'
	res.sendFile(file)
})

app.get('/API/state_pattern', (req,res) => {
	let file = '/vietnh/model/state_pattern/' + req.headers.user_id + '-' + req.headers.home_id + '_state.csv'
	res.sendFile(file)
})

module.exports = app;
