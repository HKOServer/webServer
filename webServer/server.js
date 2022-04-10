import config from "./config.js";
import { asyncQuery, genSalt, hashPassword } from "./db.js";

import express from "express";
import session from "express-session";
import ejs from "ejs";

import SQL from 'sql-template-strings';
import fetch from "node-fetch";
import { body, validationResult } from "express-validator";

//#region Setup
let app = express();

app.engine("ejs", (path, data, cb) => {
    ejs.renderFile("./views/layouts/layout.ejs", {
        body: path,
        ...data
    }, {
        cache: true
    }, cb);
});
//#endregion

//#region pipeline
app.use(express.urlencoded({ extended: true }));
app.use(session(config.session));
//#endregion

app.use(express.static("./static"));

app.get("/", (req, res) => {
    res.render("pages/index.ejs", {
        account: req.session.account
    });
});

//#region login

/**
 * @param {Request} req 
 * @param {Response} res 
 * @param {(error?: any) => void} next 
 */
function requiresLogin(req, res, next) {
    if (!req.session.bearer_token) {
        res.status(401).render('pages/error.ejs', {
            status: 401,
            msg: "Unauthorized"
        });
    } else {
        next();
    }
}

app.get("/login", (req, res) => {
    res.redirect(`https://discord.com/api/oauth2/authorize` +
        `?client_id=${config.oauth2.client_id}` +
        `&redirect_uri=${encodeURIComponent(config.oauth2.redirect_uri)}` +
        `&response_type=code&scope=${encodeURIComponent(config.oauth2.scopes.join(" "))}`);
});

app.get("/login/callback", async (req, res) => {
    const accessCode = req.query.code;
    if (!accessCode) return res.redirect("/");

    let token;
    try {
        const data = new URLSearchParams();
        data.append("client_id", config.oauth2.client_id);
        data.append("client_secret", config.oauth2.client_secret);
        data.append("grant_type", "authorization_code");
        data.append("redirect_uri", config.oauth2.redirect_uri);
        data.append("scope", "identify");
        data.append("code", accessCode);

        token = await (await fetch("https://discord.com/api/oauth2/token", {
            method: "POST",
            body: data
        })).json();

        if (token.error) {
            console.error(token);
            return;
        }
    } catch (e) {
        console.error(e);
        res.sendStatus(500);
        return;
    }

    const userInfo = await (await fetch("https://discord.com/api/users/@me", {
        headers: {
            authorization: `${token.token_type} ${token.access_token}`,
        },
    })).json();

    req.session.discord_info = userInfo;
    req.session.bearer_token = token;

    let account = await asyncQuery(SQL`SELECT username FROM account WHERE id = ${BigInt(userInfo.id)}`);
    req.session.account = account[0];

    console.log(account);

    if (!req.session.account) {
        res.redirect("/create");
    } else {
        res.redirect("/manage");
    }
});

app.get("/logout", (req, res) => {
    if (!req.session.bearer_token) {
        res.redirect("/");
    } else {
        req.session.destroy();
        res.redirect("/");
    };
});

app.get("/create", requiresLogin, (req, res) => {
    if (req.session.account) {
        res.redirect("/manage");
    } else {
        res.render("pages/create.ejs", {
            errors: []
        });
    }
});

app.post("/create",
    requiresLogin,
    body("username")
        .isLength({ min: 4, max: 64 }).withMessage("Username must be between 4 and 64 characters long")
        .matches(/^[0-9a-zA-Z.-]+$/).withMessage("Username can only contain the following characters:\n0-9a-zA-Z.-"),
    body("password").isLength({ min: 8, max: 32 }).withMessage("Password must be between 8 and 32 characters long"),
    async (req, res) => {
        if (req.session.account) {
            res.redirect("/");
            return;
        }

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render("pages/create.ejs", {
                errors: errors.array()
            });
        }

        let username = req.body.username.toLowerCase();

        let exists = await asyncQuery(SQL`SELECT id FROM account WHERE username = ${username}`);
        if (exists.length != 0) {
            return res.render("pages/create.ejs", {
                errors: [{
                    msg: "Username already in use"
                }]
            });
        }

        let salt = genSalt();
        let pass = hashPassword(req.body.password, salt);
        let blob = Buffer.from([...salt, ...pass]);

        asyncQuery(SQL`INSERT INTO account (id, username, password) VALUES (${BigInt(req.session.discord_info.id)}, ${username}, ${blob})`);
        req.session.account = { username };

        res.redirect("/");
    }
);

app.get("/manage", requiresLogin, (req, res) => {
    if (!req.session.account) {
        res.redirect("/create");
    } else {
        res.render("pages/manage.ejs", {
            account: req.session.account,
            errors: []
        });
    }
});
app.post("/manage/username", requiresLogin,
    body("username")
        .isLength({ min: 4, max: 64 }).withMessage("Username must be between 4 and 64 characters long")
        .matches(/^[0-9a-zA-Z.-]+$/).withMessage("Username can only contain the following characters:\n0-9a-zA-Z.-")
    , async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render("pages/manage.ejs", {
                account: req.session.account,
                errors: errors.array()
            });
        }

        let username = req.body.username.toLowerCase();

        if (username !== req.session.account.username) {
            let exists = await asyncQuery(SQL`SELECT id FROM account WHERE username = ${username}`);
            if (exists.length != 0) {
                return res.render("pages/manage.ejs", {
                    account: req.session.account,
                    errors: [{
                        msg: "Username already in use"
                    }]
                });
            }

            asyncQuery(SQL`UPDATE account SET username = ${username} WHERE id = ${BigInt(req.session.discord_info.id)}`);
            req.session.account.username = username;
        }

        res.sendStatus(200);
    });

app.post("/manage/password", requiresLogin,
    body("password").isLength({ min: 6, max: 32 }).withMessage("Password must be between 8 and 32 characters long"),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render("pages/manage.ejs", {
                account: req.session.account,
                errors: errors.array()
            });
        }

        let salt = genSalt();
        let pass = hashPassword(req.body.password, salt);
        let blob = Buffer.from([...salt, ...pass]);

        asyncQuery(SQL`UPDATE account SET password = ${blob} WHERE id = ${BigInt(req.session.discord_info.id)}`);
        res.sendStatus(200);
    });

//#endregion

//#region Patching

// get base urls
app.get('/single/leading.txt', function (req, res) {
    res.send(
        `http://127.0.0.1/ver
http://127.0.0.1/static
http://127.0.0.1/static`);
});

// get zips urls
app.get('/ver/*', function (req, res) {
    let type = req.params["0"].substr(12, 2);
    let id = req.params["0"].substr(0, 11);

    const currentVersion = "v0109090002";

    if (id != currentVersion) {
        if (type == "pc") {
            if (id == "v0000000001") {
                res.send(`v0000000002\ndata_0.tar`);
            } else if (id == "v0000000002") {
                res.send(`v0000000003\ndata_1.tar`);
            } else if (id == "v0000000003") {
                res.send(`v0000000004\ndata_2.tar`);
            } else if (id == "v0000000004") {
                res.send(`${currentVersion}\ndata_3.tar`);
            } else {
                res.send(`v0000000001\ntables.tar`);
            }
        } else {
            res.send(`${currentVersion}`);
        }
    } else {
        res.status(404).send("404 not found");
    }
});

//#endregion

// Capture All 404 errors
app.use(function (req, res, next) {
    res.status(404).render('pages/error.ejs', {
        status: 404,
        msg: "Page not found"
    });
});

let server = app.listen(80, function () {
    let host = server.address().address
    let port = server.address().port

    console.log(`Listening at http://${host}:${port}`);
});
