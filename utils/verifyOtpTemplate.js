const verifyOtpTemplate = ({otp})=>{
    return`
<p>Dear user </p>    
<p>Please verify this OTP</p>   
<a href=${otp} style="color:black;background :orange;margin-top : 10px,padding:20px,display:block">
    Verify OTP
</a>
`
}

export default verifyOtpTemplate