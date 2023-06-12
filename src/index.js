const app = require('./app');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const seedWithDummyData = require('../seeder');

dotenv.config();

//connect to DB
mongoose.set('useCreateIndex', true);
mongoose.set('useFindAndModify', false);

const url = process.env.DATABASE_URL || "mongodb://localhost:27017/users";
mongoose.connect(url,{ useNewUrlParser: true, useUnifiedTopology: true }, () => {
    console.log('connected to DB');
    seedWithDummyData();
})


app.listen(3000, () => console.log('Server running......'));
