const verifyOtpTemplate = ({ otp }) => {
    return `
      <p>Dear user,</p>    
      <p>Please use the following OTP to reset your password:</p>   
      <h2 style="color: orange; font-size: 24px;">${otp}</h2>
      <p>This OTP is valid for 1 hour.</p>
    `;
  };
  
  export default verifyOtpTemplate;
  