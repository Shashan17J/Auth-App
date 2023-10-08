const express = require("express");
const router = express.Router();

const {login, signup} = require("../controller/Auth");
const {auth, isStudent, isAdmin} = require('../middlewares/auth')

router.post("/login", login);
router.post("/signup", signup);

router.get("/test", auth, (req,res) => {
    res.json({
        success:true,
        message:"Welcome to the Protected Route"
    })
})

// Protected Routes
router.get("/student", auth, isStudent, (req,res) => {
    res.json({
        success:true,
        message:'Welcome to the Protected route for Student'
    });
});

router.get("/admin", auth, isAdmin, (req,res) => {
    res.json({
        success:true,
        message:'Welcome to the Protected route for Admin',
    });
});

module.exports = router;