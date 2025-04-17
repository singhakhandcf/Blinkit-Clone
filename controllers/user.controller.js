import UserModel from "../models/user.model";

export async function registerUser(req,res){
    try{
        const {name,email,password}=req.body;
        if(!name||!email||!password){
            return res.status(400).json({message:"Please fill required fields"});
        }
        const User=await UserModel.findOne({email});
        if(User){
            return res.status(501).json({message:"User already exists"});
        }
        await UserModel.save
    }
    catch(error){
        return res.status(500).json({message:"cannot register user",error:true,success:false});
    }
}