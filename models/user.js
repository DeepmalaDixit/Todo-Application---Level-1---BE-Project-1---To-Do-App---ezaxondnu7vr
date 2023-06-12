var mongoose = require("mongoose");

/*
Complete your other field here

1. name should be a string and required
2. password should be a string and required
3. role should be a string and it can have only 2 values ('user', 'admin') and default should be user
4. email should be a string and required.
5. Also Enable timestamps which will store the date of document created and updated.
*/

var userSchema = mongoose.Schema({
  //Write your code here.
name: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
  email: {
    type: String,
    required: true,
  },
}, {
  timestamps: true,
});

module.exports = mongoose.model("User", userSchema);
