export default {
    oauth2: {
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
        secret: "",
        cookie: {
            maxAge: 7 * 24 * 60 * 60 * 1000
        },
        resave: false,
        saveUninitialized: false
    },
    cacheSize: 100
};
