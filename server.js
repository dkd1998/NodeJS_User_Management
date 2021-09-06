const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv').config();
const multer = require('multer');


const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads')
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname)
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
    cb(null, true);
  } else {
    cb(null, false);
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 1024 * 1024 * 5
  },
  fileFilter: fileFilter
});


app.use(express.json());
app.use(express.static(__dirname + '/public'));
app.use('/uploads', express.static('uploads'));


let id = 1;
const users = [];

app.post('/user/register', upload.single('profile'), async (req, res) => {
  if (users.find(user => user.email === req.body.email))
    return res.status(409).send("A user with specified email already exists, please login");
  try {
    let file_path = __dirname + "\\" + req.file.path;
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = { id: id, name: req.body.name, email: req.body.email, contact: req.body.contact, password: hashedPassword, profile_path: file_path };
    id++;
    users.push(user);

    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);


    res.status(201).json({ accessToken: accessToken, image_path: file_path });
  } catch {
    res.status(500).send();
  }
})


app.post('/user/login', async (req, res) => {
  const user = users.find(user => user.name === req.body.name);
  if (user == null) {
    return res.status(400).send('Cannot find user');
  }
  if (!(req.body.name && req.body.password)) {
    res.status(400).send("Name and Password required for login");
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);

      res.status(201).json({ accessToken: accessToken });
    } else {
      res.send('Entered password is incorrect');
    }
  } catch {
    res.status(500).send();
  }
})


app.get('/user/alluserinfo', authenticateToken, (req, res) => {
  res.json(users);
})

app.get('/user/info', authenticateToken, (req, res) => {
  const user = users.find(user => user.name === req.body.name);
  if (user == null) {
    return res.status(400).send('Cannot find user');
  } else {
    return res.json(user);
  }
})

app.put('/user/update/:id', authenticateToken, (req, res) => {
  if (req.params.id > users.length) {
    res.status(400).send("Record with given ID does not exists");
  } else if (!(req.body.name && req.body.email && req.body.contact)) {
    res.status(400).send("Name , Email, Contact number : All fields required to update a record");
  } else {
    let index = req.params.id - 1;
    users[index].name = req.body.name;
    users[index].email = req.body.email;
    users[index].contact = req.body.contact;
    res.status(200).send("Records updated successfully");
  }
})

app.put('/user/password/:id', authenticateToken, async (req, res) => {
  if (req.params.id > users.length) {
    res.status(400).send("Record with given ID does not exists or empty database");
  }
  if (!(req.body.email && req.body.contact && req.body.password)) {
    res.status(400).send("Email and Contact number required to change a password");
  }

  let index = req.params.id - 1;


  if (users[index].email === req.body.email && users[index].contact === req.body.contact) {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    users[index].password = hashedPassword;
    res.status(200).send("Password changed successfully");
  }
  else {
    res.status(400).send("Email / Contact details incorrect!");
  }
})


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.status(401).send("A token is required to access record");

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).send("Incorrect token");
    next();
  })
}

app.listen(process.env.PORT);
console.log("App started running on PORT :" + process.env.PORT)