import sendEmail from "../config/sendEmail.js";
import UserModel from "../models/user.model.js";
import bcrypt from "bcryptjs";
import verifyEmailTemplate from "../utils/verifyEmailTemplate.js";
import { Router } from "express";

export class UserController{
    
    constructor(){
        this.router=Router();
        this.configureRoutes();
    }

    configureRoutes(){
        this.router.post("/register",this.registerUser);
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
            const verifyEmailUrl=`${process.env.FRONTEND_URL}/verify-email?codes=${save?._id}`;
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

}

