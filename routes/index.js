const router = require('express').Router();

router.use('/user', require('./userRoutes'));

module.exports = router;