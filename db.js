import mysql from "mysql";
import crypto from "crypto";
import config from "./config.js";

var pool = mysql.createPool({
    ...config.db,
    supportBigNumbers: true,
    bigNumberStrings: true
});

pool.on('error', (err) => {
    console.error(err);
});

/**
 * @param {string} query 
 * @returns {Promise<any[]>}
 */
export function asyncQuery(query) {
    return new Promise((resolve, reject) => {
        pool.query(query, (error, result, fields) => {
            if (error) {
                reject(error);
            } else {
                resolve(result);
            }
        })
    });
}

export function genSalt() {
    return crypto.randomBytes(16);
}

export function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(Buffer.from(password), salt, 10000, 256 / 8, "sha1");
}
