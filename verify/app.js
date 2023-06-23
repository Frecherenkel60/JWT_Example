const JsonWebToken = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const express = require("express");

const client = jwksClient({
  jwksUri: "http://localhost:3000/.well-known/jwks.json",
});

const verify = async (token, kid) => {
  try {
    const key = await client.getSigningKey(kid);
    const signingKey = key.getPublicKey();

    const answer = JsonWebToken.verify(
      token,
      signingKey,
      { algorithms: ["RS256"] },
      (err, decoded) => {
        if (err) {
          return { jwt: null, success: false, err: err };
        }

        return { jwt: decoded, success: true, err: null };
      }
    );

    return answer;
  } catch (err) {
    return { jwt: null, success: false, err: err };
  }
};

const app = express();
const port = 3001;

app.get("/verify", async (req, res) => {
  const token = req.query.token;
  const decoded = JsonWebToken.decode(token, { complete: true });
  const answer = await verify(token, decoded.header.kid);
  const { jwt, success, err } = answer;

  res.send({
    jwt: jwt,
    kid: decoded.header.kid,
    verified: success,
    error: err,
  });
});

app.listen(port, () => {
  console.log(`Verify app listening at http://localhost:${port}`);
});
