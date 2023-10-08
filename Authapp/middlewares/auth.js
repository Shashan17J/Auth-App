// auth, is Student, isAdmin

const jwt = require("jsonwebtoken");
require("dotenv").config();

exports.auth = (req,res,next) => {
    try{
        // extract JWT Token

        const token = req.body.token || req.body.token || req.header("Authorization").replace("Bearer", "");

        // if we wnat to fetch token from cookies then
        // const token = req.cookies.token
 
        if(!token) {
            return res.status(400).json({
                success:false,
                message:'Token Missing',
            });
        }

        // verify token
        try{
            const payload = jwt.verify(token, process.env.JWT_SECRET);
            console.log(payload);

            // storing token back to user bcoz we will check on another middleware & access the role.
            // JTW->decode->get Payload->add payload in request body
            req.user = payload;

        } catch(error){
            return res.status(401).json({
                success:false,
                message:'token is invalid',
            })
        }
        //jump to next middleware 
        next();
    } catch(error) {
        return res.status(401).json({
            success:false,
            message:'Something went wrong, while verify the token',
        });
    }
}


// both isStudent and isAdmin used for Authorization
exports.isStudent = (req,res,next) => {
    try{
        if(req.user.role !== "Student") {
            return res.status(401).json({
                success:false,
                message:"This is a protected route for students",
            })
        }
        next();
    } catch(error) {
        return res.status(500).json({
            success:false,
            message:"User Role is not matching",
        })
    }
}

exports.isAdmin = (req,res,next) => {
    try{
        if(req.user.role !== "Admin") {
            return res.status(401).json({
                success:false,
                message:"This is a protected route for admin",
            })
        }
        next();
    } catch(error) {
        return res.status(500).json({
            success:false,
            message:"User Role is not matching",
        })
    }
}