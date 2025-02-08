const express = require("express");
const bodyParser = require("body-parser")
const session = require('express-session');
const path = require('path');
const { Parser } = require('./parser'); 
const { exec } = require('child_process');

const app = express()
const port = 1234


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'frontend/css')));
app.use(express.static(path.join(__dirname, 'frontend/js')));
app.use(express.static(path.join(__dirname, 'frontend/dashboard/dist')));
app.use(express.static(path.join(__dirname, 'frontend/dashboard/assets')));


app.use(session({
    secret: "jabfhasb@#$%^&*(JHSDASA3rt2384298347",  
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } 
}));

const users = [{ username: 'a', password: "a" }];



app.get('/', (req, res) => {
    res.redirect("/login")
});

app.post('/',  (req, res) => {
    res.redirect("/login")
});

app.get('/login', async (req, res) => {
    
    if (req.session && req.session.user) {
        return res.redirect('/dashboard?page=1')
    }
    return res.sendFile(path.join(__dirname, 'frontend', 'login.html'));
});

app.post('/login',  (req, res) => {
    console.log(req.body)
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    //console.log(u,user.password)
    console.log(username,password)
    if (user && user.password === password) {
        req.session.user = username;
        return res.redirect('/dashboard?page=1')
    }
    res.status(401).send('Invalid credentials');
});

app.get('/dashboard', (req, res) => {
    if (!(req.session && req.session.user)) {
        return res.redirect('/login')
    }
    const pageNumber = req.query.page;
    if (pageNumber === '1') {
        return res.sendFile(path.join(__dirname, 'frontend', 'dashboard','html','index.html')); 
    } 
    else if (pageNumber === '2') {
        return res.sendFile(path.join(__dirname, 'frontend', 'dashboard','html','icon-material.html'));
    } 
    else {
        return res.status(400).send('Invalid Request');
    }

});

app.get('/data', async (req,res) => {
    const data = await Parser();
    return res.status(200).json(data)

})

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.send('Error while logging out');
      }
      res.redirect("/login");
    });
  });


app.get('/service-toggle', (req, res) => {
    const state = req.query.state; // "ON" or "OFF"

    console.log(`Service state changed to: ${state}`);

    if (state === "ON") {
        exec('/root/new/init.sh', (error, stdout, stderr) => {
            if (error) {
                console.error(`Error executing init.sh: ${error.message}`);
                return res.status(500).json({ error: 'Failed to start service' });
            }
            console.log(`init.sh output: ${stdout}`);
            return res.json({ message: 'Service started successfully' });
        });
    } else if (state === "OFF") {
        exec('/root/new/kill.sh', (error, stdout, stderr) => {
            if (error) {
                console.error(`Error executing kill.sh: ${error.message}`);
                return res.status(500).json({ error: 'Failed to stop service' });
            }
            console.log(`kill.sh output: ${stdout}`);
            return res.json({ message: 'Service stopped successfully' });
        });
    } else {
        return res.status(400).json({ error: 'Invalid state. Use "ON" or "OFF".' });
    }
});

app.listen(port, () => {
    console.log(`LINSEC running on http://localhost:${port}`);

});




// filename, malwaretype,filetype,reason, timestamp