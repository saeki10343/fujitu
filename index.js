const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

const db = new sqlite3.Database('./users.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        password TEXT,
        nickname TEXT,
        comment TEXT
    )`);

    db.get('SELECT * FROM users WHERE user_id = ?', ['TaroYamada'], (err, row) => {
        if (!row){
            db.run(`INSERT INTO users VALUES (?, ?, ?, ?)`,
                ['TaroYamada','PaSSwd4TY','たろー','僕は元気です']
            );
        }
    });
});

function validateSignupInput(user_id, password) {
    const userIdregex = /^[a-zA-Z0-9]{6,20}$/;
    const passwordRegex = /^[\x21-\x7E]{8,20}$/;

    if(!user_id || !password){
        return {valid: false, cause:'Required user_id and password'};
    }

    if(!userIdregex.test(user_id)){
        return {valid: false, cause:'Input length is incorrect'};
    }

    if(!passwordRegex.test(user_id)){
        return {valid: false, cause:'Incorrect character pattern'};
    }

    return {valid: true};
}

app.post('/signup', (req, res) => {
    const {user_id, password} = req.body;
    const validation = validateSignupInput(user_id, password);

    if (!validation.valid){
        return res.status(400).json({
            message: 'Account creation failed',
            cause: validation.cause
        });
    }

    db.get('SELECT * FROM users WHERE user_id = ?', [user_id], (err, row) =>{
        if(row){
            return res.status(400).json({
                message: 'Account creation failed',
                cause: 'Already same user_id is used'
            });
        }

        const nickname = user_id;

        db.run('INSERT INTO users (user_id, password, nickname, comment) VALUES (?, ?, ?, ?'),
            [user_id, password, nickname, ''],
            (err) => {
                if(err){
                    return res.status(500).json({message: 'Internal server error'});
                }

                res.status(200).json({
                    message: 'Account successfully created',
                    user: {
                        user_id: user_id,
                        nickname: nickname
                    }
                });
            }
        );
    });
});

const atob = (base64) => Buffer.from(base64, 'base64').toString('utf-8');

app.get('/users/:user_id', (req, res) =>{
    const user_id = req.params.use_id;
    const authHeader = req.headers.authorization;

    if(!authHeader || !authHeader.startsWith('Basic ')){
        return res.status(401).json({message: 'Authentication failed'});
    }

    const base64Credentials = authHeader.split(' ')[1];
    const decoded = atob(base64Credentials);
    const [auth_user_id, password] = decoded.split(':');

    if(!auth_user_id || !password){
        return res.status(401).json({message: 'Authentication failed'});
    }

    db.get('SELECT * FROM users WHERE user_id = ?', [user_id], (err, row) => {
        if(!row){
            return res.status(404).json({message: 'No user found'});
        }

        res.status(200).json({
            message: "User details by user_id",
            user: {
                user_id: row.use_id,
                nickname: row.nickname || row.use_id,
                comment: row.comment || ''
            }
        });
    });
});

app.patch('/users/:user_id', (req, res) =>{
    const user_id = req.params.use_id;
    const authHeader = req.headers.authorization;

    if(!authHeader || !authHeader.startsWith('Basic ')){
        return res.status(401).json({message: 'Authentication failed'});
    }

    const base64Credentials = authHeader.split(' ')[1];
    const decoded = atob(base64Credentials);
    const [auth_user_id, auth_password] = decoded.split(':');

    if(!auth_user_id || !auth_password){
        return res.status(401).json({message: 'Authentication failed'});
    }

    if(auth_user_id !== user_id){
        return res.status(403).json({message: 'No permission for update'})
    }

    db.get('SELECT * FROM users WHERE user_id = ?', [user_id], (err, row) => {
        if(!row){
            return res.status(404).json({message: 'No user found'});
        }

        if(row.password !== auth_password){
            return res.status(401).json({message: 'Authentication failed'});
        }

        const {user_id, password, nickname, comment} = req.body;

        if(user_id !== undefined || password !== undefined){
            return res.status(400).json({
                message: 'User updation failed',
                cause: 'Not updatable user_id and password'
            });
        }

        if(nickname !== undefined && comment !== undefined){
            return res.status(400).json({
                message: 'User updation failed',
                cause: 'Required nickname or comment'
            });
        }

        const isValidText = (text, maxLength) =>
            typeof text === 'string' &&
            text.length <= maxLength &&
            /^[^\x00-\x1F\x7F]*$/.test(text);

        let newNickname = row.nickname;
        let newComment = row.comment;

        if (nickname !== undefined){
            if (nickname === ''){
                newNickname = row.user_id;
            }else if (!isValidText(nickname, 30)){
                return res.status(400).json({
                    message: 'User updation failed',
                    cause: 'Invalid nickname or comment'
                });
            }else{
                newNickname = nickname;
            }
        }

        if (comment !== undefined){
            if (comment === ''){
                newComment = '';
            }else if (!isValidText(comment, 30)){
                return res.status(400).json({
                    message: 'User updation failed',
                    cause: 'Invalid nickname or comment'
                });
            }else{
                newComment = nickname;
            }
        }

        db.run('UPDATE users SET nickname = ?, comment = ? WHERE user_id = ?',
            [newNickname, newComment, auth_user_id],
            function(err){
                if(err){
                    return res.status(500).json({message: 'Database update failed'});
                }

                res.status(200).json({
                    message: "User successfully updated",
                    user: {
                        nickname: newNickname,
                        comment: newComment
                    }
                });
            }
        );
    });
});

app.post('/close', (req, res) => {
    const authHeader = req.headers.authorization;

    if(!authHeader || !authHeader.startsWith('Basic ')){
        return res.status(401).json({message: 'Authentication failed'});
    }

    const base64Credentials = authHeader.split(' ')[1];
    const decoded = atob(base64Credentials);
    const [auth_user_id, auth_password] = decoded.split(':');

    if(!auth_user_id || !auth_password){
        return res.status(401).json({message: 'Authentication failed'});
    }

    db.get('SELECT * FROM users WHERE user_id = ?', [user_id], (err, row) =>{
        if(!row || row.password !== password){
            return res.status(401).json({
                message: 'Authentication failed',
            });
        }

        db.run('DELETE FROM users WHERE user_id = ?', [user_id], function(err){
            if (err) return res.status(500).json({message: 'Internal server error'});

            res.status(200).json({message: 'Account and user successfully removed'});
        }
        );
    });
});

app.listen(port, ()=> console.log(`Server listening on port ${port}`));