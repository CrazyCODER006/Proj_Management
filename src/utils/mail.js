import Mailgen from "mailgen";
import nodemailer from "nodemailer"


const sendEmail = async(options) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "task manager",
      link: "https://taskmanagelink.com"
    }
  })

  const emailTextual = mailGenerator.generatePlaintext(options.mailgenContent)
  const emailHtml = mailGenerator.generate(options.mailgenContent)

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth: {
      user: process.env.MAILTRAP_SMTP_USER,
      pass: process.env.MAILTRAP_SMTP_PASS,
    },
  });

  const mail = {
    from: "mail.taskmanager@example.com",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml
  }

  try {
    await transporter.sendMail(mail)
  } catch (error) {
    console.error("Email service failed. Make sure to provide MailTRAP credentials to .env file");
    console.error("Error: ",error);
  }
};


const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to our app! We're excited to have you on board.",
      action: {
        instructions: "To verify your email plz click on the following button",
        button: {
          color: "#22BC66",
          text: "verify your email",
          link: verificationUrl,
        },
      },
      outro: "need help, or have questions? just reply to the email.",
    },
  };
};


const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro: "We got a request to reset the password of your account.",
      action: {
        instructions: "To reset your password plz click on the following button or link",
        button: {
          color: "#fa5a04",
          text: "reset password",
          link: passwordResetUrlUrl,
        },
      },
      outro: "need help, or have questions? just reply to the email.",
    },
  };
};

export {
    emailVerificationMailgenContent,
    forgotPasswordMailgenContent,
    sendEmail,
};