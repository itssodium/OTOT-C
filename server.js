const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

app.use(express.json())
const TOKEN = "authenticate-token-key"

const posts = [
    {
        username: 'user1',
        password: 'password1',
        roles: ['admin']
    },
    {
        username: 'user2',
        password: 'password2',
        roles: ['viewer', 'commentor']
    },
    {
        username: 'user3',
        password: 'password3',
        roles: ['editor']
    }
]

app.get('/edit', authenticateToken, authorizeToken('admin', 'editor'), (req, res) => {
    res.status(200).send('you have permission')
})

app.get('/view', authenticateToken, authorizeToken('admin', 'editor', 'viewer', 'commentor'), (req, res) => {
    res.status(200).send('you have permission')
})

app.get('/add', authenticateToken, authorizeToken('admin'), (req, res) => {
    res.status(200).send('you have permission')
})

app.get('/comment', authenticateToken, authorizeToken('commentor'), (req, res) => {
    res.status(200).send('you have permission')
})

app.post('/login', (req, res) => {
    const username = req.body.username
    const password = req.body.password

    const correctCredentials = posts.some(post => post.username === username && post.password === password)

    if (!correctCredentials) {
        return res.status(401).send('Please check your username and/or password')
    }

    const user = {name: username, password: password}
    const accessToken = jwt.sign(user, TOKEN)
    res.json({accessToken: accessToken})
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) {
        return res.staus(401).send('Pls login before accessing this page')
    }

    jwt.verify(token, TOKEN, (err, user) => {
        if (err) {
            return res.status(401).send('Pls login before accessing this page')
        }
        full_user = posts.filter(post => post.username === user.name)[0]
        req.user = full_user
        next()
    })
}

function authorizeToken(... roles) {
    return (req, res, next) => {
        user = req.user
        user_roles = user.roles
        const authorized = roles.some(role => user_roles.includes(role))
        if (!authorized) {
            return res.status(403).send('Sorry you do not have permission')
        }
        next()
    }
}

app.listen(3000)
