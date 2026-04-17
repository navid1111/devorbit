import nodemailer from "nodemailer";

// Updated to support HTML content
export const sendEmail = async (to: string, subject: string, text: string, html?: string) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      secure: true,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Logo URL from cloudinary
    const logoUrl = "https://res.cloudinary.com/dzqgzquno/image/upload/email_turfmania_jtzoj4.png";
    const motto = "Your Game. Your Turf. Your Time.";

    // Create footer HTML with logo and motto
    const footerHtml = `
      <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; font-family: Arial, sans-serif;">
        <img src="${logoUrl}" alt="TurfMania Logo" style="width: 150px; height: auto; margin-bottom: 15px;" />
        <p style="color: #4a9d61; font-size: 16px; font-weight: bold;">${motto}</p>
        <p style="color: #888; font-size: 12px;">© ${new Date().getFullYear()} TurfMania. All rights reserved.</p>
      </div>
    `;

    // Combine provided HTML with the footer, or convert text to HTML if no HTML provided
    const fullHtmlContent = html 
      ? `${html}${footerHtml}`
      : `<div style="font-family: Arial, sans-serif; line-height: 1.6;">${text.replace(/\n/g, '<br>')}</div>${footerHtml}`;

    const message = {
      from: process.env.EMAIL_USER,
      to,
      subject,
      text, // Plain text version
      html: fullHtmlContent, // HTML version with footer
    };

    await transporter.sendMail(message);
    console.log(`Email sent to ${to}`);
    return { success: true, message: "Email sent successfully" };
  } catch (error) {
    console.error("Error sending email:", error);
    throw new Error("Email could not be sent");
  }
};
