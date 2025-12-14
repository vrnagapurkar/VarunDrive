const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
require("dotenv").config();
const crypto = require("crypto");
const {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand
} = require("@aws-sdk/client-cognito-identity-provider");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const client = new CognitoIdentityProviderClient({
  region: process.env.AWS_REGION,
});

// -------------------- SECRET HASH --------------------
function createSecretHash(username) {
  return crypto
    .createHmac("sha256", process.env.COGNITO_CLIENT_SECRET)
    .update(username + process.env.COGNITO_CLIENT_ID)
    .digest("base64");
}

// -------------------- SIGNUP --------------------
app.post("/signup", async (req, res) => {
  const { email, preferred_username, name, password } = req.body;

  const params = {
    ClientId: process.env.COGNITO_CLIENT_ID,
    Username: email, // Username in Cognito is typically email
    Password: password,
    SecretHash: createSecretHash(email),
    UserAttributes: [
      { Name: "email", Value: email },
      { Name: "preferred_username", Value: preferred_username },
      { Name: "name", Value: name },
    ],
  };

  try {
    const response = await client.send(new SignUpCommand(params));
    res.json({ message: "Signup successful", data: response });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(400).json({ error: err.message });
  }
});

// -------------------- CONFIRM SIGNUP (optional) --------------------
app.post("/confirm", async (req, res) => {
  const { email, code } = req.body;

  const params = {
    ClientId: process.env.COGNITO_CLIENT_ID,
    Username: email,
    ConfirmationCode: code,
    SecretHash: createSecretHash(email),
  };

  try {
    const response = await client.send(new ConfirmSignUpCommand(params));
    res.json({ message: "User confirmed", data: response });
  } catch (err) {
    console.error("Confirm error:", err);
    res.status(400).json({ error: err.message });
  }
});

// -------------------- LOGIN --------------------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const params = {
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: process.env.COGNITO_CLIENT_ID,
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
      SECRET_HASH: createSecretHash(email),
    },
  };

  try {
    const response = await client.send(new InitiateAuthCommand(params));
    res.json({
      message: "Login successful",
      tokens: response.AuthenticationResult,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(400).json({ error: err.message });
  }
});

// -------------------- START SERVER --------------------
app.listen(3000, () => console.log("Server running on port 3000"));
