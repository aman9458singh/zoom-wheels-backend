const { check } = require('express-validator');
const nodemailer = require('nodemailer');

// // Helper function to build query from request parameters
function buildQueryFromParams(params) {
    // Implement logic to build the MongoDB query based on request parameters
    let query = { sellStatus: true };
    // Iterate through each parameter
    for (const [key, value] of params) {
        if (key && value) {
            query[key] = value;
        }
    }

    // Add more conditions as needed based on your data model and query parameters

    return query;
}

const sendEmail = async (subject, body, toEmails) => {
    try {
        // Replace these values with your SMTP server details
        const smtpTransporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'salesmafiaonline@gmail.com',
                pass: 'peyejtysjhngtosa',
            },
        });

        const mailOptions = {
            from: 'salesmafiaonline@gmail.com',
            to: toEmails.join(', '),
            subject: subject,
            text: `From: Zoom Wheels\nSubject: ${subject}\n\n${body}`,
        };

        // Send the email
        await smtpTransporter.sendMail(mailOptions);

        return { success: true, message: 'Email sent successfully.' };
    } catch (error) {
        console.error(error);
        return { success: false, error: 'Internal Server Error' };
    }
}

const validateContactUs = [
    check('fullName').exists().notEmpty(),
    check('email').exists().notEmpty().isEmail(),
    check('contactNumber').exists().notEmpty().isNumeric().isLength({ min: 10, max: 12 }),
    check('subject').exists().notEmpty(),
    check('message').exists().notEmpty(),
  ];

module.exports = { buildQueryFromParams, sendEmail,validateContactUs };