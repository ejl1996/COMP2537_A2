require("./utils.js");

const url = require('url');

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const ObjectId = require('mongodb').ObjectId;
const usersModel = require('./models/w2users');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
console.log(usersModel)
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

app.set('view engine', 'ejs');

//req.body need this to parse (app.post) ex. req.body.username
app.use(express.urlencoded({ extended: false }));

// initially was /session, now /test in mongoURL
var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@clustera1.squca6a.mongodb.net/test`,
    // mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/test`,
    crypto: {
        secret: mongodb_session_secret
    }
})

//handles cookies. Ex. req.session.cookies. **would have to parse cookies ourselves otherwise.  
app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

//AUTHENTICATION
function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

//session validation
function sessionValidation(req, res, next) {
    //if valid session call next action
    if (isValidSession(req)) {
        next();
    }
    //otherwise don't render and redirect to login
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    //return req.session.user_type = "admin";
    if (req.session.user_type == "admin") {
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

const navLinks = [
    { name: "Home", link: "/" },
    { name: "Cats", link: "/cats" },
    { name: "Login", link: "/login" },
    { name: "Admin", link: "/admin" },
    { name: "404", link: "/dne" },
]

app.use("/", (req, res, next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
});

app.get('/', (req, res) => {
    console.log(req.url);
    console.log(url.parse(req.url));
    res.render("home.ejs");
});

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
    }

    if (randomNum == 1) {
        res.render("hello.ejs", {
            x: nameOfUser,
            a: "/fluffy.gif",
            b: "/socks.gif",
            c: "/cat3.jpg"

        })
    }

    else if (randomNum == 2) {
        res.render("hello.ejs", {
            x: nameOfUser,
            a: "/fluffy.gif",
            b: "/socks.gif",
            c: "/cat3.jpg"
        })
    }

    else if (randomNum == 3) {
        res.render("hello.ejs", {
            x: nameOfUser,
            a: "/fluffy.gif",
            b: "/socks.gif",
            c: "/cat3.jpg"
        })
    }
});

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
});

app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    console.log(req.body)
    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const arrListOfUsers = await userCollection.find({}).project().toArray();
    console.log("hello")
    console.log(arrListOfUsers);
    var currentUser;
    for (i = 0; i < arrListOfUsers.length; i++) {
        console.info(arrListOfUsers[i].username);
        console.log(arrListOfUsers[i].user_type);
        if (arrListOfUsers[i].username == username) {
            currentUser = arrListOfUsers[i];
        }
    }

    for (i = 0; i < arrListOfUsers.length; i++) {
        const isPasswordValid = bcrypt.compareSync(password, currentUser.password)
        if (currentUser.username == username) {
            if (isPasswordValid) {
                req.session.authenticated = true;
                req.session.username = currentUser.username;
                req.session.user_type = currentUser.user_type;
                //req.session.email = email;
                req.session.cookie.maxAge = expireTime;
                if (req.session.user_type == 'admin') {
                    res.redirect('/admin');
                    return;
                } else {
                    res.redirect('/members');
                    return;
                }
            }
            else if (!isPasswordValid) {
                req.session.authenticated = false;
                res.redirect('/login');
                return;
            }
        }
    }
});

//this middleware protects login page and sub-routes of this one
app.use('/loggedin', sessionValidation);
app.get('/loggedin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.render("loggedin.ejs");
});

app.get('/loggedin/info', (req, res) => {
    res.render("loggedin-info");
});

app.get('/logoutuser', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find({}).project().toArray();
    res.render('admin.ejs', { title: "Admin Page", listOfUsers: result, })
});

app.get('/admin/promote/:id', async (req, res) => {
    const id = req.params.id;
    await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { user_type: "admin" } });
    res.redirect('/admin');
});

app.get('/admin/demote/:id', async (req, res) => {
    const id = req.params.id;
    await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { user_type: "user" } });
    res.redirect('/admin');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404).render("404.ejs");
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});