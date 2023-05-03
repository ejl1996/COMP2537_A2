require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 4000;

const app = express();

const Joi = require("joi");

const expireTime = 60 * 60 * 1000;  //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

console.log(mongodb_password)
console.log(mongodb_user)
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

// initially was /session, now /test in mongoURL 
app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@clustera1.squca6a.mongodb.net/test`,
    // mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/test`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

function isValidSession(req) {
    if (req.sesion.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    //return req.session.user_type = "admin";
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        //403 forbidden
        res.render("errorMessage.ejs", { error: "Not Authorized" });
        return;
    }
    else {
        next();
    }
}

app.get('/', (req, res) => {
    res.render("home.ejs")
})

app.get('/cats', (req, res) => {
    res.render("cats.ejs");
});

app.get('/login', (req, res) => {
    res.render("login.ejs");
});

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.render("nosql.ejs")
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("nosqlinj.ejs");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.render("username.ejs");
});

app.get('/logout', (req, res) => {
    if (req.session.authenticated) {
        req.session.destroy(err => {
            if (err) {
                res.status(400).send('')
            } else {
                res.status(200).redirect('/')
            }
        });
    } else {
        res.end()
    }
})

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.render("email.ejs")
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.render("submit.ejs", {
            x: req.body.email
        })
    }
});

app.get('/createUser', (req, res) => {
    res.render("createuser.ejs")
})

const authenticatedOnly = (req, res, next) => {
    var authenticated = req.session.authenticated
    if (!authenticated) {
        console.log("kicked out by middleware")
        res.redirect('/');
        return
    }
    else {
        console.log("middleware says logged in")
        next();
    }
};

app.use('/members', authenticatedOnly);

app.get('/members', authenticatedOnly, (req, res) => {
    var cat = req.params.id;
    var randomNum = Math.floor(Math.random() * 3) + 1;
    var nameOfUser = req.session.username
    var authenticated = req.session.authenticated
    var html = `<h1>Hello ${nameOfUser}</h1>`
    var html1 = `<a href="/logoutuser" class="btn btn-primary">Sign out</a>`
    var members = `<form> <a href="/members"> Go to Members Area</a>
        </form >
        `
    if (!authenticated) {
        res.redirect('/');
        //return
    }
    if (randomNum == 1) {
        res.render("hello.ejs", {
            x: nameOfUser,
            a: "/fluffy.gif",
            b: "/socks.gif",
            c: "/cat3.jpg"

        })
        //res.send(html + "<img src='/fluffy.gif' style='width:250px;'>" + "<br>" + html1 + "<br>" + members);
    }

    else if (randomNum == 2) {
        res.render("hello.ejs", {
            x: nameOfUser,
            a: "/fluffy.gif",
            b: "/socks.gif",
            c: "/cat3.jpg"
        })
        //res.send(html + "<img src='/socks.gif' style='width:250px;'>" + "<br>" + html1 + "<br>" + members);
    }
    else if (randomNum == 3) {
        res.render("hello.ejs", {
            x: nameOfUser,
            a: "/fluffy.gif",
            b: "/socks.gif",
            c: "/cat3.jpg"
        })
        //res.send(html + "<img src='/cat3.jpg' style='width:250px;'>" + "<br>" + html1 + "<br>" + members);
    }
});

//app.get('/test', (req, res) => {
//var x = 5;

//if (x == 5) {
//res.send("Hello");
//return;
//} 
//res.send("bye");
//});

app.get('/login', (req, res) => {
    var invalidEmailAndPassword = req.query.invalidEmailAndPassword;
    var invalidPassword = req.query.invalidPassword;
    if (invalidEmailAndPassword == 1) {
        res.render("login.ejs", {
            x: "<br> Email and password not found."
        })
    }
    else if (invalidPassword == 1) {
        res.render("login.ejs", {
            x: "<br> Invalid password."
        })
    }
});

app.post('/submitUser', async (req, res) => {
    console.log('Submit user')
    console.log('hello world')
    console.log(req.body)
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/createUser");
        return;
    } else {
        var hashedPassword = await bcrypt.hash(password, saltRounds);
        await userCollection.insertOne({ username: username, password: hashedPassword, email: email });
        console.log("Inserted user");

        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect("/members")
        return;
    }
    // var html = "successfully created user";
    // res.send(html);
});

app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        res.render("usernotfound.ejs");
        //console.log("user not found");
        //res.redirect("/login");
        return;
    }
    else if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        res.render();
        //console.log("incorrect password");
        //res.redirect("/login");
        return;
    }
});

app.use('/loggedin', sessionValidation);
app.get('/loggedin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.render("loggedin.ejs")
});

app.get('/logoutuser', (req, res) => {
    req.session.destroy();
    res.redirect('/');
    //var html = `
    //You are logged out.
    //`;
    //res.send(html);
});

//app.use('/admin');
//app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
//const result = await userCollection.find().project({ username: 1, _id: 1 })
//res.render("admin.ejs", { users: result });
//});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    render("404.ejs");
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});