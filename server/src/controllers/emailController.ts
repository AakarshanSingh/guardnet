import nodemailer from "nodemailer";

export const sendEmail = async (
  email: string,
  url: string,
  results: string
) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER, // Your email
        pass: process.env.EMAIL_PASS, // Your email password
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: `Scan Results for ${url}`,
      text: `The scan results for ${url} are as follows:\n\n${results}`,
    };

    await transporter.sendMail(mailOptions);
    console.log("Email sent successfully");
  } catch (error) {
    console.error(`Error sending email: ${error}`);
    throw error;
  }
};
