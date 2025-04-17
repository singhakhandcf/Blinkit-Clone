import sendEmail from "../config/sendEmail.js";
import UserModel from "../models/user.model.js";
import bcrypt from "bcryptjs";
import verifyEmailTemplate from "../utils/verifyEmailTemplate.js";
import { Router } from "express";
import generatedAccessToken from "../utils/generatedAccessToken.js";
import genertedRefreshToken from "../utils/generatedRefreshToken.js";
import auth from "../middleware/auth.js";

export class UserController{
    
    constructor(){
        this.router=Router();
        this.configureRoutes();
    }

    configureRoutes(){
        this.router.post("/register",this.registerUser);
        this.router.post("/verify-email",this.verifyUser);
        this.router.post("/login",this.loginUser);
        this.router.post("/logout",auth,this.logoutUser)
    }
    registerUser =async(req,res)=>{
        try{
            const {name,email,password}=req.body;
            if(!name||!email||!password){
                return res.status(400).json({message:"Please fill required fields"});
            }
            const User=await UserModel.findOne({email});
            if(User){
                return res.status(501).json({message:"User already exists"});
            }
            const salt =await bcrypt.genSalt(10);
            const hashPassword=await bcrypt.hash(password,salt);
            const payload={
                name,
                email,
                password:hashPassword
            }
    
            const newUser=new UserModel(payload)
            const save=await newUser.save();
            const verifyEmailUrl=`${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`;
            const verifyEmail= await sendEmail({
                sendTo:email,
                subject:"Verify Email",
                html: verifyEmailTemplate({
                    name,
                    url:verifyEmailUrl
                })
            })
            return res.status(200).json({
                message:"User Registered Sucessfully",
                error:false,
                success:true,
                data:save
            })
        }
        catch(error){
            return res.status(500).json({message:"cannot register user",error:true,success:false});
        }
    }

    verifyUser=async(req,res)=>{
        try{
            const {code}=req.query;
            console.log(code);
            const user =await UserModel.find({_id:code});

            if(!user){
                return res.status(404).json({message:"User not found"});
            }

            const updateUser=await UserModel.updateOne({_id:code},{
                verify_email:true
            })

            return res.status(201).json({message:"Verified User"});

        }
        catch(error){
            return res.status(500).json({message:"Verification failed",error:true,success:false});
        }
    }

    loginUser=async(req,res)=>{
        try{
            const {name,email,password}=req.body;
            if(!name||!email||!password){
                return res.status(400).json({message:"Please fill required fields"});
            }
            const User=await UserModel.findOne({name,email});
            if(!User){
                return res.status(404).json({message:"User Not Found!"});
            }

            if(User.status!=="Active"){
                return res.status(401).json({message:"This account is not active. Please activate the account"});
            }

            const checkPassword=await bcrypt.compare(password,User.password);
            if(!checkPassword){
                return res.status(402).json({message:"Wrong Password entered"});
            }

            const accesstoken = await generatedAccessToken(User._id)
            const refreshToken = await genertedRefreshToken(User._id)

            const updateUser = await UserModel.findByIdAndUpdate(User?._id,{
                last_login_date : new Date()
            })

            const cookiesOption = {
                httpOnly : true,
                secure : true,
                sameSite : "None"
            }
            res.cookie('accessToken',accesstoken,cookiesOption)
            res.cookie('refreshToken',refreshToken,cookiesOption)

            return res.status(202).json({
                message:"Logged in Successfully",
                data:{
                    accesstoken,
                    refreshToken
                }
            });
        }
        catch(error){
            return res.status(500).json({message:`Cannot Login User ${error.message}`,error:true,success:false});
        }
    }

    logoutUser=async(req,res)=>{
        try{
            const userid = req.userId //middleware

            const cookiesOption = {
                httpOnly : true,
                secure : true,
                sameSite : "None"
            }

            res.clearCookie("accessToken",cookiesOption)
            res.clearCookie("refreshToken",cookiesOption)

            const removeRefreshToken = await UserModel.findByIdAndUpdate(userid,{
                refresh_token : ""
            })

            return res.status(202).json({
                message : "Logout successfully",
            })
        }
        catch(error){
            res.status(501).json({
                message:`Failed to Logout: ${error.message}`,
                error:true
            })
        }
    }

}

