const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const { Op } = require('sequelize');
const sendEmail = require('helpers/send-email');
const db = require('helpers/db');
const Role = require('helpers/role');
const axios = require("axios")

//const logo = require("../helpers/logo1.png")

module.exports = {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAll,
    getById,
    create,
    update,
    delete: _delete,
    transact,
    returnUrl, 
    transactionHistory
};

async function authenticate({ email, password, ipAddress }) {
    const account = await db.Account.scope('withHash').findOne({ where: { email } });

    if (!account || !account.isVerified || !(await bcrypt.compare(password, account.passwordHash))) {
        throw 'Email or password is incorrect';
    }

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = generateJwtToken(account);
    const refreshToken = generateRefreshToken(account, ipAddress);

    // save refresh token
    await refreshToken.save();

    // return basic details and tokens
    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

async function refreshToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);
    const account = await refreshToken.getAccount();

    // replace old refresh token with a new one and save
    const newRefreshToken = generateRefreshToken(account, ipAddress);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();
    await newRefreshToken.save();

    // generate new jwt
    const jwtToken = generateJwtToken(account);

    // return basic details and tokens
    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: newRefreshToken.token
    };
}

async function revokeToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);

    // revoke token and save
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    await refreshToken.save();
}

async function transact(params, user, ipAddress, origin) {
    const transaction = new db.Transaction(params)
    transaction.createdByIP = ipAddress
    transaction.accountId = user.id
    transaction.status = "Initiated"
    await transaction.save()

    const account = await db.Account.findOne({ where: { id: user.id } });

    await sendTransactionInitialEmail(account, origin)
}

async function returnUrl(params) {
    const transaction = await db.Transaction.findOne({ where: { invoiceID: params.invoiceNo } })

    const account = await db.Account.findOne({ where: { id: transaction.accountId } })

    transaction.paymentResponds = params
    await transaction.save()

    if (params.result === "Y") {
        getOrderID(params)
        setTimeout(() => {
            sendMomo(transaction)
            transaction.save()
        }, 9000)
        
        setTimeout(() => {
            if (transaction.sendResponds.statuscode == 202) {
                    transaction.updatedAt = Date.now()
                    transaction.status = "Completed"
                    transaction.save()
                    sendTransactionCompletedEmail(account)
                } else {
                    transaction.updatedAt = Date.now()
                    transaction.status = "Payment Failed"
                    transaction.save()
                    sendTransactionFailedEmail(account)
                }
        }, 108000);

    } else {
        transaction.status = "Failed"
        transaction.updatedAt = Date.now()
        await transaction.save()
        sendTransactionFailedEmail(account)
    }

}

async function getOrderID(params) {

    const transaction = await db.Transaction.findOne({ where: { invoiceID: params.invoiceNo } })

    var data = JSON.stringify({ "api_token": "FJqAXdDCBPGtoqOApBUamc", "service": "momo" });

    var config = {
        method: 'post',
        url: 'https://portal.ekiosk.africa/api/initiate2',
        headers: {
            'Content-Type': 'application/json',
            'Cookie': '__cfduid=d870e46367a5940b04040071352fc56691605524899'
        },
        data: data
    };

    axios(config)
        .then(function (response) {
            transaction.orderID = response.data.data.orderid
            transaction.status = "Completing Transaction"
            transaction.save()
        })
        .catch(function (error) {
            console.log(error);
        });
}

function sendMomo(transaction) {

    if (transaction.status === "Completing Transaction") {
        let data = JSON.stringify({ "api_token": "FJqAXdDCBPGtoqOApBUamc", "service": "mtn-momo", "destination": `${transaction.addressReceiver}`, "cashAmount": `${transaction.volumeReceived}`, "orderid": `${transaction.orderID}` });

        let config = {
            method: 'post',
            url: 'https://portal.ekiosk.africa/api/transact',
            headers: {
                'Content-Type': 'application/json'
            },
            data: data
        };

        axios(config)
            .then((response) => {
                transaction.sendResponds = response.data
                transaction.amountPaid = response.data.data.cash
                transaction.volumeReceived = response.data.data.volume
                transaction.fees =  response.data.data.fee                
                transaction.save()
            })
            .catch((error) => {
                console.log(error);
            });
    }
}

async function transactionHistory (user){
    const transactions = await db.Transaction.findAll({where: { accountId: user.id}})
    
    if (!transactions) throw "History Unavailable"

    return transactions.map(x => transactionDetails(x))  /// transactionDetailsbasicDetails(x));
}

async function register(params, origin) {
    // validate
    if (await db.Account.findOne({ where: { email: params.email } })) {
        // send already registered error in email to prevent account enumeration
        return await sendAlreadyRegisteredEmail(params.email, origin);
    }

    // create account object
    const account = new db.Account(params);

    // first registered account is an admin
    const isFirstAccount = (await db.Account.count()) === 0;
    account.role = isFirstAccount ? Role.Admin : Role.User;
    account.verificationToken = randomTokenString();

    // hash password
    account.passwordHash = await hash(params.password);

    // save account
    await account.save();

    // send email
    await sendVerificationEmail(account, origin);
}

async function verifyEmail({ token }) {
    const account = await db.Account.findOne({ where: { verificationToken: token } });

    if (!account) throw 'Verification failed';

    account.verified = Date.now();
    account.verificationToken = null;
    await account.save();
}

async function forgotPassword({ email }, origin) {
    const account = await db.Account.findOne({ where: { email } });

    // always return ok response to prevent email enumeration
    if (!account) return;

    // create reset token that expires after 24 hours
    account.resetToken = randomTokenString();
    account.resetTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await account.save();

    // send email
    await sendPasswordResetEmail(account, origin);
}

async function validateResetToken({ token }) {
    const account = await db.Account.findOne({
        where: {
            resetToken: token,
            resetTokenExpires: { [Op.gt]: Date.now() }
        }
    });

    if (!account) throw 'Invalid token';

    return account;
}

async function resetPassword({ token, password }) {
    const account = await validateResetToken({ token });

    // update password and remove reset token
    account.passwordHash = await hash(password);
    account.passwordReset = Date.now();
    account.resetToken = null;
    await account.save();
}

async function getAll() {
    const accounts = await db.Account.findAll();
    return accounts.map(x => basicDetails(x));
}

async function getById(id) {
    const account = await getAccount(id);
    return basicDetails(account);
}

async function create(params) {
    // validate
    if (await db.Account.findOne({ where: { email: params.email } })) {
        throw 'Email "' + params.email + '" is already registered';
    }

    const account = new db.Account(params);
    account.verified = Date.now();

    // hash password
    account.passwordHash = await hash(params.password);

    // save account
    await account.save();

    return basicDetails(account);
}

async function update(id, params) {
    const account = await getAccount(id);

    // validate (if email was changed)
    if (params.email && account.email !== params.email && await db.Account.findOne({ where: { email: params.email } })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    // hash password if it was entered
    if (params.password) {
        params.passwordHash = await hash(params.password);
    }

    // copy params to account and save
    Object.assign(account, params);
    account.updated = Date.now();
    await account.save();

    return basicDetails(account);
}

async function _delete(id) {
    const account = await getAccount(id);
    await account.destroy();
}

// helper functions

async function getAccount(id) {
    const account = await db.Account.findByPk(id);
    if (!account) throw 'Account not found';
    return account;
}

async function getRefreshToken(token) {
    const refreshToken = await db.RefreshToken.findOne({ where: { token } });
    if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
    return refreshToken;
}

async function hash(password) {
    return await bcrypt.hash(password, 10);
}

function generateJwtToken(account) {
    // create a jwt token containing the account id that expires in 15 minutes
    return jwt.sign({ sub: account.id, id: account.id }, config.secret, { expiresIn: '15m' });
}

function generateRefreshToken(account, ipAddress) {
    // create a refresh token that expires in 7 days
    return new db.RefreshToken({
        accountId: account.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(account) {
    const { id, title, firstName, lastName, email, role, created, updated, isVerified } = account;
    return { id, title, firstName, lastName, email, role, created, updated, isVerified };
}

function transactionDetails(transaction){
    const { id, invoiceID, orderID, serviceType, addressReceiver, amountPaid, volumeReceived, fees, paymentResponds, sendResponds, status, createdByIP, createdAt, updatedAt, accountId } = transaction
    return { id, invoiceID, orderID, serviceType, addressReceiver, amountPaid, volumeReceived, fees, paymentResponds, sendResponds, status, createdByIP, createdAt, updatedAt, accountId }
}

async function sendVerificationEmail(account, origin) {
    let message;
    let verifyUrl
    if (origin) {
        verifyUrl = `${origin}/account/verify-email?token=${account.verificationToken}`;
        message = `<p>Please click the below link to verify your email address:</p>
                   <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to verify your email address with the <code>/account/verify-email</code> api route:</p>
                   <p><code>${account.verificationToken}</code></p>`;
    }

    await sendEmail({
        to: account.email,
        subject: 'Trust Remit Sign-up - Verify Email',
        html: `
        <!DOCTYPE html>
        <html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
        <head>
          <meta charset="utf-8">
          <meta http-equiv="x-ua-compatible" content="ie=edge">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <meta name="x-apple-disable-message-reformatting">
          <title>Confirm Your Email</title>
          <!--[if mso]>
          <xml>
            <o:OfficeDocumentSettings>
              <o:AllowPNG/>
              <o:PixelsPerInch>96</o:PixelsPerInch>
            </o:OfficeDocumentSettings>
          </xml>
          <style>
            table {border-collapse: collapse;}
            .spacer,.divider {mso-line-height-rule:exactly;}
            td,th,div,p,a {font-size: 13px; line-height: 22px;}
            td,th,div,p,a,h1,h2,h3,h4,h5,h6 {font-family:"Segoe UI",Helvetica,Arial,sans-serif;}
          </style>
          <![endif]-->
        
          <style type="text/css">
        
            @import url('https://fonts.googleapis.com/css?family=Lato:300,400,700|Open+Sans');
            @media only screen {
              .col, td, th, div, p {font-family: "Open Sans",-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI","Roboto","Helvetica Neue",Arial,sans-serif;}
              .webfont {font-family: "Lato",-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI","Roboto","Helvetica Neue",Arial,sans-serif;}
            }
        
            img {border: 0; line-height: 100%; vertical-align: middle;}
            #outlook a, .links-inherit-color a {padding: 0; color: inherit;}
            .col {font-size: 13px; line-height: 22px; vertical-align: top;}
        
            .hover-scale:hover {transform: scale(1.2);}
            .star:hover a, .star:hover ~ .star a {color: #FFCF0F!important;}
        
            @media only screen and (max-width: 600px) {
              u ~ div .wrapper {min-width: 100vw;}
              .wrapper img {width: 100%!important; height: auto!important;}
              .container {width: 100%!important; -webkit-text-size-adjust: 100%;}
            }
        
            @media only screen and (max-width: 480px) {
              .col {
                box-sizing: border-box;
                display: inline-block!important;
                line-height: 20px;
                width: 100%!important;
              }
              .col-sm-1 {max-width: 25%;}
              .col-sm-2 {max-width: 50%;}
              .col-sm-3 {max-width: 75%;}
              .col-sm-third {max-width: 33.33333%;}
              .col-sm-auto {width: auto!important;}
              .col-sm-push-1 {margin-left: 25%;}
              .col-sm-push-2 {margin-left: 50%;}
              .col-sm-push-3 {margin-left: 75%;}
              .col-sm-push-third {margin-left: 33.33333%;}
        
              .full-width-sm {display: table!important; width: 100%!important;}
              .stack-sm-first {display: table-header-group!important;}
              .stack-sm-last {display: table-footer-group!important;}
              .stack-sm-top {display: table-caption!important; max-width: 100%; padding-left: 0!important;}
        
              .toggle-content {
                max-height: 0;
                overflow: auto;
                transition: max-height .4s linear;
                -webkit-transition: max-height .4s linear;
              }
              .toggle-trigger:hover + .toggle-content,
              .toggle-content:hover {max-height: 999px!important;}
        
              .show-sm {
                display: inherit!important;
                font-size: inherit!important;
                line-height: inherit!important;
                max-height: none!important;
              }
              .hide-sm {display: none!important;}
        
              .align-sm-center {
                display: table!important;
                float: none;
                margin-left: auto!important;
                margin-right: auto!important;
              }
              .align-sm-left {float: left;}
              .align-sm-right {float: right;}
        
              .text-sm-center {text-align: center!important;}
              .text-sm-left {text-align: left!important;}
              .text-sm-right {text-align: right!important;}
        
              .nav-sm-vertical .nav-item {display: block!important;}
              .nav-sm-vertical .nav-item a {display: inline-block; padding: 5px 0!important;}
        
              .h1 {font-size: 32px !important;}
              .h2 {font-size: 24px !important;}
              .h3 {font-size: 16px !important;}
        
              .borderless-sm {border: none!important;}
              .height-sm-auto {height: auto!important;}
              .line-height-sm-0 {line-height: 0!important;}
              .overlay-sm-bg {background: #232323; background: rgba(0,0,0,0.4);}
        
              .p-sm-0 {padding: 0!important;}
              .p-sm-8 {padding: 8px!important;}
              .p-sm-16 {padding: 16px!important;}
              .p-sm-24 {padding: 24px!important;}
              .pt-sm-0 {padding-top: 0!important;}
              .pt-sm-8 {padding-top: 8px!important;}
              .pt-sm-16 {padding-top: 16px!important;}
              .pt-sm-24 {padding-top: 24px!important;}
              .pr-sm-0 {padding-right: 0!important;}
              .pr-sm-8 {padding-right: 8px!important;}
              .pr-sm-16 {padding-right: 16px!important;}
              .pr-sm-24 {padding-right: 24px!important;}
              .pb-sm-0 {padding-bottom: 0!important;}
              .pb-sm-8 {padding-bottom: 8px!important;}
              .pb-sm-16 {padding-bottom: 16px!important;}
              .pb-sm-24 {padding-bottom: 24px!important;}
              .pl-sm-0 {padding-left: 0!important;}
              .pl-sm-8 {padding-left: 8px!important;}
              .pl-sm-16 {padding-left: 16px!important;}
              .pl-sm-24 {padding-left: 24px!important;}
              .px-sm-0 {padding-right: 0!important; padding-left: 0!important;}
              .px-sm-8 {padding-right: 8px!important; padding-left: 8px!important;}
              .px-sm-16 {padding-right: 16px!important; padding-left: 16px!important;}
              .px-sm-24 {padding-right: 24px!important; padding-left: 24px!important;}
              .py-sm-0 {padding-top: 0!important; padding-bottom: 0!important;}
              .py-sm-8 {padding-top: 8px!important; padding-bottom: 8px!important;}
              .py-sm-16 {padding-top: 16px!important; padding-bottom: 16px!important;}
              .py-sm-24 {padding-top: 24px!important; padding-bottom: 24px!important;}
            }
          </style>
        </head>
        <body style="box-sizing:border-box;margin:0;padding:0;width:100%;word-break:break-word;-webkit-font-smoothing:antialiased;">
        
        <div style="display:none;font-size:0;line-height:0;"><!-- Add your inbox preview text here --></div>
        
        <table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
          <tr>
            <td class="px-sm-16" align="center" bgcolor="#EEEEEE">
              <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
                <tr>
                  <td class="px-sm-8" align="left" bgcolor="#EEEEEE">
                    <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
                    <table cellpadding="0" cellspacing="0" role="presentation" width="100%">
                      <tr>
                        <td class="col" align="center" width="100%">
                          <a href="https://example.com">
                            <img src="https://dummyimage.com/188x84/0CBACF/FFFFFF" alt="Header Logo" width="94">
                          </a>
                        </td>
                      </tr>
                    </table>
                    <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
        
        <table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
          <tr>
            <td align="center" bgcolor="#EEEEEE" class="px-sm-16">
              <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
                <tr>
                  <td bgcolor="#0072FF" style="background: linear-gradient(to right, #00C6FF, #0072FF);">
                    <!--[if gte mso 9]>
                    <v:rect xmlns:v="urn:schemas-microsoft-com:vml" fill="true" stroke="false" style="width:600px;">
                    <v:fill type="gradient" color="#0072FF" color2="#00C6FF" angle="90" />
                    <v:textbox style="mso-fit-shape-to-text:true" inset="0,0,0,0">
                    <div><![endif]-->
                    <div class="spacer line-height-sm-0 py-sm-16" style="line-height: 32px;">&zwnj;</div>
                    <table cellpadding="0" cellspacing="0" role="presentation" width="100%">
                      <tr>
                        <td align="center" class="px-sm-16" style="padding: 0 96px;">
                          <h1 class="webfont h1" style="color: #FFFFFF; font-size: 36px; font-weight: 300; line-height: 100%; margin: 0;">Confirm your email</h1>
                        </td>
                      </tr>
                    </table>
                    <div class="spacer line-height-sm-0 py-sm-16" style="line-height: 40px;">&zwnj;</div>
                    <!--[if gte mso 9]></div></v:textbox></v:rect><![endif]-->
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
        
        <table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
          <tr>
            <td class="px-sm-16" align="center" bgcolor="#EEEEEE">
              <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
                <tr>
                  <td class="px-sm-8" align="left" bgcolor="#FFFFFF" style="padding: 0 24px;">
                    <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
                    <table cellpadding="0" cellspacing="0" role="presentation" width="100%">
                      <tr>
                        <td class="col px-sm-16" align="center" width="100%" style="padding: 0 64px;">
                          <h2 style="color: #000; font-size: 20px; font-weight: 300; line-height: 28px; margin: 0 0 24px;">Hi ${account.firstName}</h2>
                          <p style="color: #888888; font-size: 16px; line-height: 24px; margin: 0;">You just created a new customer account at Trust Remit. All you have to do now is activate it:</p>
                          <div class="spacer" style="line-height: 32px;">&zwnj;</div>
                          <table cellpadding="0" cellspacing="0" role="presentation">
                            <tr>
                              <td class="webfont hover-scale" bgcolor="#0072FF" style="border-radius: 3px; transition: all 0.3s ease-in-out 0s; mso-padding-alt: 6px 32px 12px;">
                                <a href="${verifyUrl}" style="color: #FFFFFF; display: inline-block; font-size: 14px; font-weight: 700; padding: 12px 32px; text-decoration: none;">Activate my account</a>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
                    <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
        
        <table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
          <tr>
            <td class="px-sm-16" align="center" bgcolor="#EEEEEE">
              <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
                <tr>
                  <td class="divider py-sm-16 px-sm-16" bgcolor="#FFFFFF" style="padding: 24px 32px;">
                    <div style="background: #EEEEEE; height: 1px; line-height: 1px;">&zwnj;</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
        
        <table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
          <tr>
            <td class="px-sm-16" align="center" bgcolor="#EEEEEE">
              <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
                <tr>
                  <td class="px-sm-8" bgcolor="#FFFFFF" style="padding: 0 24px;">
                    <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
                    <table cellpadding="0" cellspacing="0" role="presentation" width="100%">
                      <tr>
                        <td class="col" align="center" width="100%" style="padding: 0 8px;">
                          <div>
                            <img src="https://dummyimage.com/188x42" alt="Footer logo" width="94">
                          </div>
                          <div class="spacer" style="line-height: 12px;">&zwnj;</div>
                          <p style="color: #888888; margin: 0;">
                            &copy; 2020 TrustRemit. All Rights Reserved.
                          </p>
                          <p class="links-inherit-color" style="color: #888888; margin: 0;">
                            126-130 Crosby Street, Soho New York City, NY 10012, U.S.
                          </p>
                          <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
                          <div>
                            <a href="https://example.com" style="text-decoration: none;">
                              <img src="pinterest-light.png" alt="Pinterest" width="32">
                            </a>
                            <a href="https://example.com" style="text-decoration: none;">
                              <img src="twitter-light.png" alt="Twitter" width="32">
                            </a>
                            <a href="https://example.com" style="text-decoration: none;">
                              <img src="instagram-light.png" alt="YouTube" width="32">
                            </a>
                          </div>
                          <div class="spacer" style="line-height: 16px;">&zwnj;</div>
                        </td>
                      </tr>
                    </table>
                    <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
                  </td>
                </tr>
                <tr>
                  <td class="px-sm-8" bgcolor="#EEEEEE" style="padding: 0 24px;">
                    <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
                    <table cellpadding="0" cellspacing="0" role="presentation" width="100%">
                      <tr>
                        <td class="col" align="center" width="100%" style="padding: 0 8px;">
                          <p style="color: #888888; margin: 0;">
                            Questions? Reply to this email or contact us at <a href="https://example.com" style="color: #888888; text-decoration: underline;">support@ghana.com</a>
                          </p>
                        </td>
                      </tr>
                    </table>
                    <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
        
        <table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
          <tr>
            <td class="px-sm-16" align="center" bgcolor="#EEEEEE">
              <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
                <tr>
                  <td class="spacer height-sm-auto py-sm-8" bgcolor="#EEEEEE" height="24"></td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
        
        </body>
        </html>
        `
    });
}

async function sendAlreadyRegisteredEmail(email, origin) {
    let message;
    if (origin) {
        message = `<p>If you don't know your password please visit the <a href="${origin}/account/forgot-password">forgot password</a> page.</p>`;
    } else {
        message = `<p>If you don't know your password you can reset it via the <code>/account/forgot-password</code> api route.</p>`;
    }

    await sendEmail({
        to: email,
        subject: 'Trust Remit - Email Already Registered',
        html: `<!DOCTYPE html>
        <html lang="en">
        
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Email Template</title>
            <link rel="preconnect" href="https://fonts.gstatic.com">
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500&display=swap" rel="stylesheet">
        </head>
        
        <body style="margin: 0; padding: 0; font-family: 'Roboto';">
            <table role="presentation" align="center" style="border-collapse: collapse;" border="0" cellpadding="0"
                cellspacing='0' width="600">
                <tr>
                    <td align="center" bgcolor="#ffffff">
                        <h1 color="white"><img src="https://ghana.com/wp-content/uploads/2020/01/logo-black.png" width ="75" alt="logo" />
                            Already Registered Email</h1>
                    </td>
                </tr>
                <tr>
                    <td bgcolor="#e7e7e7" style="padding: 40px;">
                        <!-- <p style="margin: 0;">Second Two</p> -->
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse: collapse;">
                            <tr>
                                <td style="padding: 20px;">
                                    <h3 style="margin: 0;">Hello ${account.title} ${account.firstName} ${account.lastName},</h3>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding: 30px ;">
                                    <p style="margin: 0;"><strong>${email} has already been registered</strong>
                                    ${message}
                                    </p>
                                </td>
                                
                            </tr>
                            <tr>
                                <td>
                                   <p><i>If this was not done by you, contact <a href="mailto:support@ghana.com">us</a></i></p> 
                                </td>
                            </tr>
                            <tr>
                                <td bgcolor="#333333" style="padding: 30px;">
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                        style="border-collapse: collapse;">
                                        <tr>
                                            <td width=100%>
                                                <p style="margin: 0; color: white;">Transfer Money With Ease.&reg; 
                                                    &copy; 2020 Trust Transfer.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
        </body>
        
        </html>`
    });
}

async function sendPasswordResetEmail(account, origin) {
    //let message;
    //if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${account.resetToken}`;
        // message = `<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
        //            <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    // } else {
    //     message = `<p>Please use the below token to reset your password with the <code>/account/reset-password</code> api route:</p>
    //                <p><code>${account.resetToken}</code></p>`;
    // }

    await sendEmail({
        to: account.email,
        subject: 'Trust Remit  - Reset Password',
        html: `
        <!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
  <meta charset="utf-8">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="x-apple-disable-message-reformatting">
  <title>Reset Your Password</title>
  <!--[if mso]>
  <xml>
    <o:OfficeDocumentSettings>
      <o:AllowPNG/>
      <o:PixelsPerInch>96</o:PixelsPerInch>
    </o:OfficeDocumentSettings>
  </xml>
  <style>
    table {border-collapse: collapse;}
    .spacer,.divider {mso-line-height-rule:exactly;}
    td,th,div,p,a {font-size: 13px; line-height: 22px;}
    td,th,div,p,a,h1,h2,h3,h4,h5,h6 {font-family:"Segoe UI",Helvetica,Arial,sans-serif;}
  </style>
  <![endif]-->

  <style type="text/css">

    @import url('https://fonts.googleapis.com/css?family=Lato:300,400,700|Open+Sans');
    @media only screen {
      .col, td, th, div, p {font-family: "Open Sans",-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI","Roboto","Helvetica Neue",Arial,sans-serif;}
      .webfont {font-family: "Lato",-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI","Roboto","Helvetica Neue",Arial,sans-serif;}
    }

    img {border: 0; line-height: 100%; vertical-align: middle;}
    #outlook a, .links-inherit-color a {padding: 0; color: inherit;}
    .col {font-size: 13px; line-height: 22px; vertical-align: top;}

    .hover-scale:hover {transform: scale(1.2);}
    .star:hover a, .star:hover ~ .star a {color: #FFCF0F!important;}

    @media only screen and (max-width: 600px) {
      u ~ div .wrapper {min-width: 100vw;}
      .wrapper img {width: 100%!important; height: auto!important;}
      .container {width: 100%!important; -webkit-text-size-adjust: 100%;}
    }

    @media only screen and (max-width: 480px) {
      .col {
        box-sizing: border-box;
        display: inline-block!important;
        line-height: 20px;
        width: 100%!important;
      }
      .col-sm-1 {max-width: 25%;}
      .col-sm-2 {max-width: 50%;}
      .col-sm-3 {max-width: 75%;}
      .col-sm-third {max-width: 33.33333%;}
      .col-sm-auto {width: auto!important;}
      .col-sm-push-1 {margin-left: 25%;}
      .col-sm-push-2 {margin-left: 50%;}
      .col-sm-push-3 {margin-left: 75%;}
      .col-sm-push-third {margin-left: 33.33333%;}

      .full-width-sm {display: table!important; width: 100%!important;}
      .stack-sm-first {display: table-header-group!important;}
      .stack-sm-last {display: table-footer-group!important;}
      .stack-sm-top {display: table-caption!important; max-width: 100%; padding-left: 0!important;}

      .toggle-content {
        max-height: 0;
        overflow: auto;
        transition: max-height .4s linear;
        -webkit-transition: max-height .4s linear;
      }
      .toggle-trigger:hover + .toggle-content,
      .toggle-content:hover {max-height: 999px!important;}

      .show-sm {
        display: inherit!important;
        font-size: inherit!important;
        line-height: inherit!important;
        max-height: none!important;
      }
      .hide-sm {display: none!important;}

      .align-sm-center {
        display: table!important;
        float: none;
        margin-left: auto!important;
        margin-right: auto!important;
      }
      .align-sm-left {float: left;}
      .align-sm-right {float: right;}

      .text-sm-center {text-align: center!important;}
      .text-sm-left {text-align: left!important;}
      .text-sm-right {text-align: right!important;}

      .nav-sm-vertical .nav-item {display: block!important;}
      .nav-sm-vertical .nav-item a {display: inline-block; padding: 5px 0!important;}

      .h1 {font-size: 32px !important;}
      .h2 {font-size: 24px !important;}
      .h3 {font-size: 16px !important;}

      .borderless-sm {border: none!important;}
      .height-sm-auto {height: auto!important;}
      .line-height-sm-0 {line-height: 0!important;}
      .overlay-sm-bg {background: #232323; background: rgba(0,0,0,0.4);}

      .p-sm-0 {padding: 0!important;}
      .p-sm-8 {padding: 8px!important;}
      .p-sm-16 {padding: 16px!important;}
      .p-sm-24 {padding: 24px!important;}
      .pt-sm-0 {padding-top: 0!important;}
      .pt-sm-8 {padding-top: 8px!important;}
      .pt-sm-16 {padding-top: 16px!important;}
      .pt-sm-24 {padding-top: 24px!important;}
      .pr-sm-0 {padding-right: 0!important;}
      .pr-sm-8 {padding-right: 8px!important;}
      .pr-sm-16 {padding-right: 16px!important;}
      .pr-sm-24 {padding-right: 24px!important;}
      .pb-sm-0 {padding-bottom: 0!important;}
      .pb-sm-8 {padding-bottom: 8px!important;}
      .pb-sm-16 {padding-bottom: 16px!important;}
      .pb-sm-24 {padding-bottom: 24px!important;}
      .pl-sm-0 {padding-left: 0!important;}
      .pl-sm-8 {padding-left: 8px!important;}
      .pl-sm-16 {padding-left: 16px!important;}
      .pl-sm-24 {padding-left: 24px!important;}
      .px-sm-0 {padding-right: 0!important; padding-left: 0!important;}
      .px-sm-8 {padding-right: 8px!important; padding-left: 8px!important;}
      .px-sm-16 {padding-right: 16px!important; padding-left: 16px!important;}
      .px-sm-24 {padding-right: 24px!important; padding-left: 24px!important;}
      .py-sm-0 {padding-top: 0!important; padding-bottom: 0!important;}
      .py-sm-8 {padding-top: 8px!important; padding-bottom: 8px!important;}
      .py-sm-16 {padding-top: 16px!important; padding-bottom: 16px!important;}
      .py-sm-24 {padding-top: 24px!important; padding-bottom: 24px!important;}
    }
  </style>
</head>
<body style="box-sizing:border-box;margin:0;padding:0;width:100%;word-break:break-word;-webkit-font-smoothing:antialiased;">

<div style="display:none;font-size:0;line-height:0;"><!-- Add your inbox preview text here --></div>

<table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
  <tr>
    <td class="px-sm-16" align="center" bgcolor="#EEEEEE">
      <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
        <tr>
          <td class="px-sm-8" align="left" bgcolor="#EEEEEE">
            <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
            <table cellpadding="0" cellspacing="0" role="presentation" width="100%">
              <tr>
                <td class="col" align="center" width="100%">
                  <a href="https://example.com">
                    <img src="https://dummyimage.com/188x84/0CBACF/FFFFFF" alt="Header Logo" width="94">
                  </a>
                </td>
              </tr>
            </table>
            <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

<table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
  <tr>
    <td align="center" bgcolor="#EEEEEE" class="px-sm-16">
      <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
        <tr>
          <td bgcolor="#0072FF" style="background: linear-gradient(to right, #00C6FF, #0072FF);">
            <!--[if gte mso 9]>
            <v:rect xmlns:v="urn:schemas-microsoft-com:vml" fill="true" stroke="false" style="width:600px;">
            <v:fill type="gradient" color="#0072FF" color2="#00C6FF" angle="90" />
            <v:textbox style="mso-fit-shape-to-text:true" inset="0,0,0,0">
            <div><![endif]-->
            <div class="spacer line-height-sm-0 py-sm-16" style="line-height: 32px;">&zwnj;</div>
            <table cellpadding="0" cellspacing="0" role="presentation" width="100%">
              <tr>
                <td align="center" class="px-sm-16" style="padding: 0 96px;">
                  <h1 class="webfont h1" style="color: #FFFFFF; font-size: 36px; font-weight: 300; line-height: 100%; margin: 0;">Reset Your password</h1>
                </td>
              </tr>
            </table>
            <div class="spacer line-height-sm-0 py-sm-16" style="line-height: 40px;">&zwnj;</div>
            <!--[if gte mso 9]></div></v:textbox></v:rect><![endif]-->
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

<table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
  <tr>
    <td class="px-sm-16" align="center" bgcolor="#EEEEEE">
      <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
        <tr>
          <td class="px-sm-8" align="left" bgcolor="#FFFFFF" style="padding: 0 24px;">
            <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
            <table cellpadding="0" cellspacing="0" role="presentation" width="100%">
              <tr>
                <td class="col px-sm-16" align="center" width="100%" style="padding: 0 64px;">
                  <h2 style="color: #000; font-size: 20px; font-weight: 300; line-height: 28px; margin: 0 0 24px;">Hi ${account.firstName}</h2>
                  <p style="color: #888888; font-size: 16px; line-height: 24px; margin: 0;">We received a request to reset your password. Use the button below to setup a new password for your account::</p>
                  <div class="spacer" style="line-height: 32px;">&zwnj;</div>
                  <table cellpadding="0" cellspacing="0" role="presentation">
                    <tr>
                      <td class="webfont hover-scale" bgcolor="#0072FF" style="border-radius: 3px; transition: all 0.3s ease-in-out 0s; mso-padding-alt: 6px 32px 12px;">
                        <a href="${resetUrl}" style="color: #FFFFFF; display: inline-block; font-size: 14px; font-weight: 700; padding: 12px 32px; text-decoration: none;">Reset Password</a>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
            <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

<table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
  <tr>
    <td class="px-sm-16" align="center" bgcolor="#EEEEEE">
      <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
        <tr>
          <td class="divider py-sm-16 px-sm-16" bgcolor="#FFFFFF" style="padding: 24px 32px;">
            <div style="background: #EEEEEE; height: 1px; line-height: 1px;">&zwnj;</div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

<table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
  <tr>
    <td class="px-sm-16" align="center" bgcolor="#EEEEEE">
      <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
        <tr>
          <td class="px-sm-8" bgcolor="#FFFFFF" style="padding: 0 24px;">
            <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
            <table cellpadding="0" cellspacing="0" role="presentation" width="100%">
              <tr>
                <td class="col" align="center" width="100%" style="padding: 0 8px;">
                  <div>
                    <img src="https://dummyimage.com/188x42" alt="Footer logo" width="94">
                  </div>
                  <div class="spacer" style="line-height: 12px;">&zwnj;</div>
                  <p style="color: #888888; margin: 0;">
                    &copy; 2020 TrustRemit. All Rights Reserved.
                  </p>
                  <p class="links-inherit-color" style="color: #888888; margin: 0;">
                    126-130 Crosby Street, Soho New York City, NY 10012, U.S.
                  </p>
                  <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
                  <div>
                    <a href="https://example.com" style="text-decoration: none;">
                      <img src="pinterest-light.png" alt="Pinterest" width="32">
                    </a>
                    <a href="https://example.com" style="text-decoration: none;">
                      <img src="twitter-light.png" alt="Twitter" width="32">
                    </a>
                    <a href="https://example.com" style="text-decoration: none;">
                      <img src="instagram-light.png" alt="YouTube" width="32">
                    </a>
                  </div>
                  <div class="spacer" style="line-height: 16px;">&zwnj;</div>
                </td>
              </tr>
            </table>
            <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
          </td>
        </tr>
        <tr>
          <td class="px-sm-8" bgcolor="#EEEEEE" style="padding: 0 24px;">
            <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
            <table cellpadding="0" cellspacing="0" role="presentation" width="100%">
              <tr>
                <td class="col" align="center" width="100%" style="padding: 0 8px;">
                  <p style="color: #888888; margin: 0;">
                    Questions? Reply to this email or contact us at <a href="https://example.com" style="color: #888888; text-decoration: underline;">support@ghana.com</a>
                  </p>
                </td>
              </tr>
            </table>
            <div class="spacer line-height-sm-0 py-sm-8" style="line-height: 24px;">&zwnj;</div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

<table class="wrapper" cellpadding="0" cellspacing="0" role="presentation" width="100%">
  <tr>
    <td class="px-sm-16" align="center" bgcolor="#EEEEEE">
      <table class="container" cellpadding="0" cellspacing="0" role="presentation" width="600">
        <tr>
          <td class="spacer height-sm-auto py-sm-8" bgcolor="#EEEEEE" height="24"></td>
        </tr>
      </table>
    </td>
  </tr>
</table>

</body>
</html>

        `
    });
}

async function sendTransactionInitialEmail(account) {   
    await sendEmail({
        to: account.email,
        subject: 'Trust Remit - Transaction Initiated',
        html: `<!DOCTYPE html>
        <html lang="en">
        
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Email Template</title>
            <link rel="preconnect" href="https://fonts.gstatic.com">
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500&display=swap" rel="stylesheet">
        </head>
        
        <body style="margin: 0; padding: 0; font-family: 'Roboto';">
            <table role="presentation" align="center" style="border-collapse: collapse;" border="0" cellpadding="0"
                cellspacing='0' width="600">
                <tr>
                    <td align="center" bgcolor="#ffffff">
                        <h1 color="white"><img src="https://ghana.com/wp-content/uploads/2020/01/logo-black.png" width ="75" alt="logo" />
                            Transaction Initiated </h1>
                    </td>
                </tr>
                <tr>
                    <td bgcolor="#e7e7e7" style="padding: 40px;">
                        <!-- <p style="margin: 0;">Second Two</p> -->
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse: collapse;">
                            <tr>
                                <td style="padding: 20px;">
                                    <h3 style="margin: 0;">Hello ${account.title} ${account.firstName} ${account.lastName},</h3>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding: 30px ;">
                                    <p style="margin: 0;">The transaction has been initiated. Please make payment</p>
                                </td>
                                
                            </tr>
                            <tr>
                                <td>
                                   <p><i>If this was not done by you, contact <a href="mailto:support@ghana.com">us</a></i></p> 
                                </td>
                            </tr>
                            <tr>
                                <td bgcolor="#333333" style="padding: 30px;">
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                        style="border-collapse: collapse;">
                                        <tr>
                                            <td width=100%>
                                                <p style="margin: 0; color: white;">Transfer Money With Ease.&reg; 
                                                    &copy; 2020 Trust Transfer.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
        </body>
        
        </html>`
    });
}

async function sendTransactionCompletedEmail(account) {
    await sendEmail({
        to: account.email,
        subject: 'Trust Remit - Transaction Completed',
        html: `<!DOCTYPE html>
        <html lang="en">
        
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Email Template</title>
            <link rel="preconnect" href="https://fonts.gstatic.com">
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500&display=swap" rel="stylesheet">
        </head>
        
        <body style="margin: 0; padding: 0; font-family: 'Roboto';">
            <table role="presentation" align="center" style="border-collapse: collapse;" border="0" cellpadding="0"
                cellspacing='0' width="600">
                <tr>
                    <td align="center" bgcolor="#ffffff">
                        <h1 color="white"><img src="https://ghana.com/wp-content/uploads/2020/01/logo-black.png" width ="75" alt="logo" />
                            Transaction Completed  </h1>
                    </td>
                </tr>
                <tr>
                    <td bgcolor="#e7e7e7" style="padding: 40px;">
                        <!-- <p style="margin: 0;">Second Two</p> -->
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse: collapse;">
                            <tr>
                                <td style="padding: 20px;">
                                    <h3 style="margin: 0;">Hello ${account.title} ${account.firstName} ${account.lastName},</h3>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding: 30px ;">
                                    <p style="margin: 0;">The transaction has been completed. Thank you for using Trust Remit</p>
                                </td>
                                
                            </tr>
                            <tr>
                                <td>
                                   <p><i>If this was not done by you, contact <a href="mailto:support@ghana.com">us</a></i></p> 
                                </td>
                            </tr>
                            <tr>
                                <td bgcolor="#333333" style="padding: 30px;">
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                        style="border-collapse: collapse;">
                                        <tr>
                                            <td width=100%>
                                                <p style="margin: 0; color: white;">Transfer Money With Ease.&reg; 
                                                    &copy; 2020 Trust Transfer.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
        </body>
        
        </html>`
    });

}

async function sendTransactionFailedEmail(account) {    
    await sendEmail({
        to: account.email,
        subject: 'Trust Remit - Transaction Failed',
        html: `<!DOCTYPE html>
        <html lang="en">
        
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Email Template</title>
            <link rel="preconnect" href="https://fonts.gstatic.com">
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500&display=swap" rel="stylesheet">
        </head>
        
        <body style="margin: 0; padding: 0; font-family: 'Roboto';">
            <table role="presentation" align="center" style="border-collapse: collapse;" border="0" cellpadding="0"
                cellspacing='0' width="600">
                <tr>
                    <td align="center" bgcolor="#ffffff">
                        <h1 color="white"><img src="https://ghana.com/wp-content/uploads/2020/01/logo-black.png" width ="75" alt="logo" />
                            Transaction Initiated </h1>
                    </td>
                </tr>
                <tr>
                    <td bgcolor="#e7e7e7" style="padding: 40px;">
                        <!-- <p style="margin: 0;">Second Two</p> -->
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse: collapse;">
                            <tr>
                                <td style="padding: 20px;">
                                    <h3 style="margin: 0;">Hello ${account.title} ${account.firstName} ${account.lastName},</h3>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding: 30px ;">
                                    <p style="margin: 0;">The transaction failed. Please try again</p>
                                </td>
                                
                            </tr>
                            <tr>
                                <td>
                                   <p><i>If this was not done by you, contact <a href="mailto:support@ghana.com">us</a></i></p> 
                                </td>
                            </tr>
                            <tr>
                                <td bgcolor="#333333" style="padding: 30px;">
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                                        style="border-collapse: collapse;">
                                        <tr>
                                            <td width=100%>
                                                <p style="margin: 0; color: white;">Transfer Money With Ease.&reg; 
                                                    &copy; 2020 Trust Transfer.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
        </body>
        
        </html>`
    });

}