var fs = require('fs');

var app = require('express')();
var server = require('http').Server(app);
var util = require('util');
var log_file = fs.createWriteStream(__dirname + '/logs/debug.log', {flags : 'w'});
var log_stdout = process.stdout;
console.log = function(d) {
	log_file.write(util.format(d) + '\n');
	log_stdout.write(util.format(d) + '\n');
};
var DATE = new Date();

var GCM = require('gcm').GCM;
var apiKey = 'AIzaSyBg4mLnceWpKL8-Lpo6nUjGfx6v86Sovtk';
var gcm = new GCM(apiKey);

var databaseUrl = "mongodb://localhost:27017/FlyerBoard";
var collections = ["users", "fliers"];
var db = require("mongojs").connect(databaseUrl, collections);

var userSessions = [];
var failedAuthAttempts = [];
var disabledSocketIDs = [];
var connectedSockets = [];

io.on('connection', function (socket) {
	console.log("new user connected");
	connectedSockets[socket.id] = true;
	socket.on('get fliers', function(msg) {
		console.log("get fliers");
		db.items.find(function(err, items) {
			if( err || !items || items.length == 0) io.to(socket.id).emit('get fliers', "No fliers were found.");
			else {
				io.to(socket.id).emit('get fliers', items);
			}
		});
	});
	socket.on('get flier', function(msg) {
		console.log("get flier");
		db.items.find({_id: msg._id}, function(err, item) {
			if( err || !item || item.length == 0) io.to(socket.id).emit('get flier', "Bad _id.");
			else {
				io.to(socket.id).emit('get flier', item);
			}
		});
	});
	socket.on('login', function(msg){
		console.log("user trying to login");
		stopBruteForce(msg.username);
		if (disabledSocketIDs[msg.username] != null) {
			if (DATE.getTime() < disabledSocketIDs[msg.username]) {
				console.log("A user tried to log in too many times");
				io.to(socket.id).emit('login', "You've failed too many times.");
				return;
			}
			else {
				disabledSocketIDs[msg.username] = null;
			}
		}
		db.users.find({username: msg.username}, function(err, users) {
			if( err || !users || users.length == 0) io.to(socket.id).emit('login', "failed to authenticate login");
			else {
				if (comparePassword(users[0].password, msg.password)) {
					var sesh = {}
					sesh.id = users[0]._id;
					sesh.authKey = determineAuthKey(sesh.id);
					sesh.username = msg.username;
					sesh.socketID = socket.id;
					userSessions[sesh.id] = sesh;
					failedAuthAttempts[msg.username] = null;
					console.log(sesh.username + " is logging in.");
					io.to(socket.id).emit('login', {authKey: sesh.authKey, id: sesh.id, username: sesh.username});
				} else {
					io.to(socket.id).emit('login', "failed to authenticate login");
				}
			}
		});
	});
	socket.on('reconnect to session', function(msg){
		console.log("user trying to reconnect");
		if (userSessions[msg.id] != null && userSessions[msg.id].authKey == msg.authKey) {
			userSessions[msg.id].socketID = socket.id;
			io.to(socket.id).emit('reconnect', "rejoined session");
		} else {
			io.to(socket.id).emit('reconnect', "failed to rejoin session");
		}
	});
	socket.on('logout', function(msg){
		// TODO clear GCM and APNS data
		console.log("logout");
		if (userSessions[msg.ID] != null && userSessions[msg.ID].authKey == msg.authKey)
				userSessions[msg.ID] = null;
	});
	socket.on('create account', function(msg){
		console.log("create account");
		db.users.find({username: msg.username}, function(err, users) {
			//verify there are no other users with username and that the email is valid
			if (users.length == 0 && validateEmail(msg.email)) {
				db.users.save({username: msg.username, password: hashPassword(msg.password), email: msg.email}, function(err, saved) {
					if( err || !saved ) console.log("User not created");
					else {
						var sesh = {}
						sesh.authKey = determineAuthKey(saved._id);
						sesh.id = saved._id;
						sesh.username = saved.username;
						userSessions[sesh.id] = sesh;
						io.to(socket.id).emit('login', {authKey: sesh.authKey, id: sesh.id, username: sesh.username});
						console.log("User created");
					}
				});
			} else {
				if (users.length != 0)
					io.to(socket.id).emit('create account', "username already taken");
				else if (!validateEmail(msg.email))
					io.to(socket.id).emit('create account', "invalid email");
			}
		});
	});
	socket.on('change email', function(msg){
		console.log("change email");
		stopBruteForce(msg.ID);
		if (disabledSocketIDs[msg.ID] != null) {
			if (DATE.getTime() < disabledSocketIDs[msg.ID]) {
				io.to(socket.id).emit('change email', "Failed to authenticate email change. You've been locked out.");
				return;
			}
			else {
				disabledSocketIDs[msg.ID] = null;
			}
		}
		if (userSessions[msg.ID] != null && userSessions[msg.ID].authKey == msg.authKey) {
			db.users.find({_id: db.ObjectId(msg.ID)}, function(err, users) {
				if (validateEmail(msg.email) && users[0].username == msg.username && comparePassword(users[0].password, msg.password)) {
					db.users.update({_id: db.ObjectId(msg.ID)}, {$set: {email: msg.email}});
					io.emit('change email', "Successfully changed email.");
				} else {
					io.to(socket.id).emit('change email', "The email you entered was not valid.");
				}
				failedAuthAttempts[msg.ID] = null;
			});
		} else {
			io.to(socket.id).emit('change email', "Failed to authenticate email change.");
		}
	});
	socket.on('change password', function(msg){
		console.log("change password");
		stopBruteForce(msg.ID);
		if (disabledSocketIDs[msg.ID] != null) {
			if (DATE.getTime() < disabledSocketIDs[msg.ID]) {
				io.to(socket.id).emit('change password', "Failed to authenticate password change. You've been locked out.");
				return;
			}
			else {
				disabledSocketIDs[msg.ID] = null;
			}
		}
		if (userSessions[msg.ID] != null && userSessions[msg.ID].authKey == msg.authKey) {
			db.users.find({_id: db.ObjectId(msg.ID)}, function(err, users) {
				if (users[0].username == msg.username && comparePassword(users[0].password, msg.password) && validatePassword(msg.newPassword) == true) {
					db.users.update({_id: db.ObjectId(msg.ID)}, {$set: {password: hashPassword(msg.newPassword)}});
					io.emit('change password', "Successfully changed password.");
				} else {
					var validateResponse = validatePassword(msg.newPassword);
					if (validateResponse != true)
						io.to(socket.id).emit('change password', validateResponse);
					else
						io.to(socket.id).emit('change password', "The old password was incorrect.");
				}
				failedAuthAttempts[msg.ID] = null;
			});
		} else {
			io.to(socket.id).emit('change password', "Failed to authenticate password change.");
		}
	});
	socket.on('set GCMregID', function(msg){
		console.log("set GCM regID");
		stopBruteForce(msg.ID);
		if (disabledSocketIDs[msg.ID] != null) {
			if (DATE.getTime() < disabledSocketIDs[msg.ID]) {
				io.to(socket.id).emit('set GCMregID', "Failed to authenticate GCM regID change. You've been locked out.");
				return;
			}
			else {
				disabledSocketIDs[msg.ID] = null;
			}
		}
		if (userSessions[msg.ID] != null && userSessions[msg.ID].authKey == msg.authKey) {
			db.users.find({_id: db.ObjectId(msg.ID)}, function(err, users) {
				db.users.update({_id: db.ObjectId(msg.ID)}, {$set: {GCMregID: msg.GCMregID}});
				io.emit('set GCMregID', "Successfully changed GCM regID.");
				failedAuthAttempts[msg.ID] = null;
			});
		} else {
			io.to(socket.id).emit('set GCMregID', "Failed to authenticate GCM regID change.");
		}
	});
	socket.on('set APNSregID', function(msg){
		console.log("set APNS regID");
		stopBruteForce(msg.ID);
		if (disabledSocketIDs[msg.ID] != null) {
			if (DATE.getTime() < disabledSocketIDs[msg.ID]) {
				io.to(socket.id).emit('set APNSregID', "Failed to authenticate APNS regID change. You've been locked out.");
				return;
			}
			else {
				disabledSocketIDs[msg.ID] = null;
			}
		}
		if (userSessions[msg.ID] != null && userSessions[msg.ID].authKey == msg.authKey) {
			db.users.find({_id: db.ObjectId(msg.ID)}, function(err, users) {
				db.users.update({_id: db.ObjectId(msg.ID)}, {$set: {APNSregID: msg.APNSregID}});
				io.emit('set APNSregID', "Successfully changed APNS regID.");
				failedAuthAttempts[msg.ID] = null;
			});
		} else {
			io.to(socket.id).emit('set APNSregID', "Failed to authenticate APNS regID change.");
		}
	});
	socket.on('new bid', function(msg){
		// TODO check to ensure all values are valid (including that they are the correct type)
		console.log("new bid");
		stopBruteForce(msg.bidder)
		if (disabledSocketIDs[msg.bidder] != null) {
			if (DATE.getTime() < disabledSocketIDs[msg.bidder]) {
				io.to(socket.id).emit('new bid', "You've failed too many times.");
				return;
			}
			else {
				disabledSocketIDs[msg.bidder] = null;
			}
		}
		// verify user session
		if (userSessions[msg.bidder] != null && userSessions[msg.bidder].authKey == msg.authKey){
			// this still needs lots of work!
			db.items.find({_id: db.ObjectId(msg._id)}, function(err, items) {
				if (parseFloat(msg.bid) > parseFloat(items[0].bidHistory[items[0].bidHistory.length - 1].bid)) {
					// send outbid notification
					console.log("considering sending an outbid notification");
					if (items[0].bidHistory[items[0].bidHistory.length - 1].bidder != msg.bidder) {
						// TODO check the othersocket
						if (userSessions[items[0].bidHistory[items[0].bidHistory.length - 1].bidder] != null && connectedSockets[userSessions[items[0].bidHistory[items[0].bidHistory.length - 1].bidder].socketID] == true) {
							console.log("sending an outbid notification");
							io.to(userSessions[items[0].bidHistory[items[0].bidHistory.length - 1].bidder].socketID).emit('outbid notification', {item: msg._id, price: msg.bid, bidder: msg.bidder});
						} else {
							// TODO send a push notification to the user's phone or an email or text
							db.users.find({_id: db.ObjectId(items[0].bidHistory[items[0].bidHistory.length - 1].bidder)}, function(err, users) {
								var GCMregID = "";
								if( err || !users) console.log(err);
								else GCMregID = users[0].GCMregID;
								var message = {
									registration_id: GCMregID, // required
									collapse_key: "You've been outbid",
									data: {
										item: msg._id,
										price: msg.bid,
										bidder: msg.bidder
									}
								};
								gcm.send(message, function(err, messageId){
									if (err) {
										console.log("Failed to send GCM");
									} else {
										console.log("Sent GCM with ID ", messageId);
									}
								});
							});
							db.users.find({_id: db.ObjectId(items[0].bidHistory[items[0].bidHistory.length - 1].bidder)}, function(err, users) {
								var APNSregID = "";
								if( err || !users) console.log(err);
								else APNSregID = users[0].APNSregID;
								// TODO send an Apple push notification
							});
						}
					}
					db.items.update({_id: db.ObjectId(msg._id)}, {$push: {bidHistory: {bid: msg.bid, bidder: msg.bidder, time: DATE.getHours() + ":" + DATE.getMinutes()}}});
					io.emit('new bid', {itemID: msg.itemID, _id: msg._id, bid: msg.bid, bidder: msg.bidder, time: DATE.getHours() + ":" + DATE.getMinutes()});
				} else {
					console.log("bidding failed with bid of " + msg.bid);
					io.to(socket.id).emit('new bid', "Your bid was not above the current high bid.");
				}
				failedAuthAttempts[msg.bidder] = null;
			});
		} else
			io.to(socket.id).emit('new bid', "failed to authenticate bid");
	});
	socket.on('disconnect', function () {
		connectedSockets[socket.id] = null;
	});
});

function authenticateIDauthKey (ID, authKey) {
	stopBruteForce(ID);
	if (disabledSocketIDs[msg.bidder] != null) {
		if (DATE.getTime() < disabledSocketIDs[msg.bidder]) {
			return false;
		}
		else {
			disabledSocketIDs[msg.bidder] = null;
		}
	}
	// verify user session
	if (userSessions[msg.bidder] != null && userSessions[msg.bidder].authKey == msg.authKey)
		return true;
	else
		return false;
}

function authenticateUsernamePass (ID, authKey) {
	stopBruteForce(ID);
	if (disabledSocketIDs[msg.bidder] != null) {
		if (DATE.getTime() < disabledSocketIDs[msg.bidder]) {
			return false;
		}
		else {
			disabledSocketIDs[msg.bidder] = null;
		}
	}
	// verify user session
	if (userSessions[msg.bidder] != null && userSessions[msg.bidder].authKey == msg.authKey)
		return true;
	else
		return false;
}

function stopBruteForce(ID) {
	if (failedAuthAttempts[ID] == null) {
		failedAuthAttempts[ID] = 1;
	}
	else if (disabledSocketIDs[ID] == null) {
		failedAuthAttempts[ID]++;
		if (failedAuthAttempts[ID] > 10) {
			//keep the user from trying to log in again for a while
			disabledSocketIDs[ID] = DATE.getTime() + (5 * 60 * 1000);
		}
	}
}

function determineID(username) {
	// TODO this DB get may have scaling issues once there are more users
	var id = "";
	db.users.find({username: username}, function(err, users) {
		if( err || !users) console.log(err);
		else
			id = users[0]._id
	});
	return id;
}

function determineAuthKey(id) {
	var key = 0;
	for (var i = 0; i < 32; i++)
		key += Math.floor(Math.random() * 10) * Math.pow(10, i);
	return id + key;
}

function validateEmail(email) {
	var hasAtAndDot = email.indexOf("@") != -1 && email.indexOf(".") != -1;
	var atAndDotSeparated = email.indexOf(".") - email.indexOf("@") > 1;
	if (hasAtAndDot && atAndDotSeparated) {
		return true;
	} else
		return false;
}

function validatePassword(password) {
	var longEnough = password.length >= 8;
	var shortEnough = password.length <= 32;
	// var regExp = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,32}$/;
	// var hasCorrectChars = password.match(regExp);
	var hasDigits = password.match(/\d/) != null;
	var hasLetters = password.match(/[a-zA-Z]/) != null;
	console.log(password + " = " + longEnough + " " + shortEnough + " " + hasDigits + " " + hasLetters);
	if (longEnough && shortEnough && hasDigits && hasLetters)
		return true;
	else {
		if (!longEnough)
			return "Password is too short.";
		if (!shortEnough)
			return "Password is too long.";
		if (!hasDigits)
			return "Password must have numbers";
		if (!hasLetters)
			return "Password must have letters.";
	}
}

function hashPassword (password) {
	return bcrypt.hashSync(password);
}

function comparePassword (correct, testing) {
	return bcrypt.compareSync(testing, correct);
}





server.listen(22846, function(){
	console.log('listening on *:22846');
});