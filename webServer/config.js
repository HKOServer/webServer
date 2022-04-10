
function randomString(length) {
    let result = '';
    let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!"§$%&/()=?*#';
    for (var i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

export default {
    oauth2: { // discord oauth keys
        client_id: "",
        client_secret: "",
        redirect_uri: "http://localhost/login/callback",
        scopes: ["identify"]
    },
    db: {
        host: 'localhost',
        user: 'root',
        password: '',
        database: 'hko'
    },
    session: {
        secret: randomString(32), // can be random because important data is only stored on the server anyway
        cookie: {
            maxAge: 7 * 24 * 60 * 60 * 1000
        },
        resave: false,
        saveUninitialized: false
    },
    server: { // https certificate
        keyPath: "",
        certPath: "",
        passphrase: ""
    }
};
