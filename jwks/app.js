const express = require("express");
const jose = require("node-jose");
const schedule = require("node-schedule");
const fs = require("fs");

const keyStore = jose.JWK.createKeyStore();

// Generate initial key
(async () => {
  const key = await keyStore.generate("RSA", 2048, {
    alg: "RS256",
    use: "sig",
  });
  console.log("Generated initial key with kid", key.kid);
  fs.writeFileSync(
    "./keys.json",
    JSON.stringify(keyStore.toJSON(true), null, "  ")
  );
})();

// Delete key with given kid at given date (in our case, 2 minutes from now)
const deleteOldKey = (date, kid) => {
  console.log(
    `Schedule deletion of key with kid ${kid} at ${new Date(date * 1000)} in ${
      date - Math.floor(Date.now() / 1000)
    } seconds`
  );
  schedule.scheduleJob(new Date(date * 1000), async () => {
    console.log("Deleting key with kid", kid, "now");
    const ks = fs.readFileSync("./keys.json");
    const keyStore = await jose.JWK.asKeyStore(ks.toString());

    // Delete token with the given kid
    const json = keyStore.toJSON(true);
    const index = json.keys.findIndex((key) => key.kid === kid);
    if (index === -1) {
      console.log("Key not found");
      return;
    }

    json.keys.splice(index, 1);
    fs.writeFileSync("./keys.json", JSON.stringify(json, null, "  "));
  });
};

// Rotate keys every 2 minutes
schedule.scheduleJob("*/2 * * * *", async () => {
  const ks = fs.readFileSync("./keys.json");
  const keyStore = await jose.JWK.asKeyStore(ks.toString());

  const newKey = await keyStore.generate("RSA", 2048, {
    alg: "RS256",
    use: "sig",
  });
  const json = keyStore.toJSON(true);
  json.keys = json.keys.reverse();

  console.log("Rotating keys: New key with kid", newKey.kid);

  fs.writeFileSync("./keys.json", JSON.stringify(json, null, "  "));
  const deletionDate = Math.floor(Date.now() / 1000) + 2 * 60;

  deleteOldKey(deletionDate, json.keys[1].kid);
});

/**
 * Set up express app
 */

const app = express();
const port = 3000;

app.use(express.json());

// Expose JWK(S)
app.get("/.well-known/jwks.json", async (req, res) => {
  const ks = fs.readFileSync("./keys.json");
  const keyStore = await jose.JWK.asKeyStore(ks.toString());

  res.send(keyStore.toJSON());
});

// Create new token
app.get("/tokens", async (req, res) => {
  const ks = fs.readFileSync("./keys.json");
  const keyStore = await jose.JWK.asKeyStore(ks.toString());

  const [key] = keyStore.all({ use: "sig" });
  const opt = { compact: true, jwk: key, fields: { typ: "jwt" } };

  const payload = JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + 2 * 60,
    iat: Math.floor(Date.now() / 1000),
    sub: "Schweig",
  });

  const token = await jose.JWS.createSign(opt, key).update(payload).final();
  res.send({ token });
});

app.listen(port, () => {
  console.log(`JWKS app listening at http://localhost:${port}`);
});
