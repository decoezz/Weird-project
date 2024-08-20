const nodemailer = require('nodemailer');
const htmlToText = require('html-to-text');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

module.exports = class Email {
  constructor(user, url) {
    this.to = user.email;
    this.firstName = user.name.split(' ')[0];
    this.url = url;
    this.from = `Ezz el dien Ahmed <${process.env.EMAIL_FROM}>`;
  }

  newTransport() {
    return nodemailer.createTransport({
      host: 'smtp-relay.brevo.com',
      port: process.env.BREVO_PORT,
      secure: false,
      auth: {
        user: process.env.BREVO_USERNAME,
        pass: process.env.BREVO_PASSWORD,
      },
    });
  }

  async send(template, subject) {
    // 1) Load HTML template
    const templatePath = path.join(
      __dirname,
      `../views/email/${template}.html`
    );
    let html = fs.readFileSync(templatePath, 'utf-8');

    // 2) Replace placeholders with actual data
    html = html
      .replace('{{firstName}}', this.firstName)
      .replace('{{url}}', this.url);

    // 3) Define email options
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      html,
      text: htmlToText.convert(html),
    };

    // 4) Create a transport and send email
    await this.newTransport().sendMail(mailOptions);
  }

  async sendWelcome() {
    await this.send('welcome', 'Welcome to the Fitness dashboard Family!');
  }

  async sendPasswordReset() {
    await this.send(
      'passwordReset',
      'Your password reset token (valid for only 10 minutes)'
    );
  }
};
