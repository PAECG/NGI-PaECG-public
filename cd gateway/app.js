const express = require("express");
const path = require("path");
const http = require("http");
const app = express();
const bodyParser = require("body-parser");
const forge = require("node-forge");
const cors = require("cors");
const fetch = require("node-fetch");
const sha256 = require("sha256");
const PORT = process.env.PORT || 5000;
//const server = require("http").createServer(app);
const WebSocket = require("ws");
app.use(express.static(path.join(__dirname, "/public")));
const server = http.createServer(app);

server.listen(PORT, () => console.log(`Started ${PORT}`));

const wss = new WebSocket.Server({ server: server });

const date = require("date-and-time");

var htmlHash, javascriptHash, policyHash;

var allPolicyContent = "";
var allJavascriptContent = "";
var htmlContent = "";
var htmlUrl,javascriptUrls,policyUrls,info_for_receipt;

var fs = require("fs");
const { Console } = require("console");
const rsa = forge.pki.rsa;
const keyPair = rsa.generateKeyPair({
  bits: 1024,
  e: 0x10001,
});

const publicKey = keyPair.publicKey;
const privateKey = keyPair.privateKey;
const publicKey_pem = forge.pki.publicKeyToPem(keyPair.publicKey);
const privateKey_pem = forge.pki.privateKeyToPem(keyPair.privateKey);

wss.on("connection", (ws) => {
  console.log("New connection from client");
  ws.send("You connected Successfully");

  ws.on("message", (data) => {
    let message = JSON.parse(data);
    let message_data = message.data;
    allpolicyUrls = message_data.policyUrls;
    javascriptUrls = message_data.javaScriptUrls;
    htmlUrl = message_data.htmlUrl;

    console.log(
      "Message Received from client title >> ",
       message.title
    );

    console.log(
      "Website type Received from client website type >> ",
        message.website_type
    );

    //noncomplaint website
    if (
      message.title == "getContentsAndHash" &&
      message.website_type == "noncompliant"
    ) {
      Promise.all([
        getHtml(htmlUrl),
        gatherJavascriptFiles(javascriptUrls),
        gatherPolicyFiles(allpolicyUrls),
      ]).then(() => {
        generateHash().then(() => {
          console.log("Gathering Files and Hashing done");
          let messageTosend = {
            title: "hashingCompleted",
            data: {
              javascriptHash: javascriptHash,
              policyHash: policyHash,
              htmlHash: htmlHash,
            },
          };
          ws.send(JSON.stringify(messageTosend));
          console.log("Hashes Sent");
        });
      });
    }

    //compliant website
    if (
      message.title == "getContentsAndHash" &&
      message.website_type == "compliant"
    ) {

       consentText=message_data.consentText;
       javascriptUrls=message_data.javaScriptUrls;
       policyUrls=message_data.policyUrls;
       htmlUrl = message_data.htmlUrl;
       info_for_receipt=message_data.info_for_receipt;

      console.log(allpolicyUrls + javascriptUrls + htmlUrl);

      Promise.all([getHtml(htmlUrl),gatherJavascriptFiles(javascriptUrls),gatherPolicyFiles(allpolicyUrls),
      ]).then(() => {
        generateHashcompliant().then(() => {
          console.log("Gathering Files and Hashing done");
          let messageTosend = {
            title: "hashingCompleted",
            data: {
              javascriptHash: javascriptHash,
              policyHash: policyHash,
              htmlHash: htmlHash,
            },
          };
          ws.send(JSON.stringify(messageTosend));
          console.log("Hashes Sent");
        });
      });
    }

    if (message.title == "signedMessage") {
      console.log(message.data);
      let user_public_key = forge.pki.publicKeyFromPem(message_data.public_key);
      let user_signed_message = message_data.signed_Data;
        let consent_details={
          htmlContent:htmlContent,javascript: allJavascriptContent,policy: allPolicyContent,PII: message_data.PII,timestamp:message_data.timestamp,nounce:message_data.nounce,info_for_receipt
      };
      console.log("Signed Message From Client");
      let messageDigest = forge.md.sha256.create();
      messageDigest.update(consent_details, 'utf8');
      let verify = user_public_key.verify(messageDigest.digest().bytes(), user_signed_message);
      // If the signature is valid then
      if (verify) {
          console.log("Signature is Valid");

          let receiptData = {
              'identifier': message_data.receiptId,
          };

          receiptData['paecg']={
              'user_public_key':message_data.public_key,
              'signed_Messaged': message_data.signed_Data,
              'DataSigned':consent_details,
              'PII':message_data.PII,
              'html':htmlContent,
              'javascript':allJavascriptContent,
              'policy':allPolicyContent,
              htmlHash,javascriptHash,policyHash
          }
          let fileName=`receipts/receipt${message_data.receiptId}.json`;
          fs.writeFileSync(fileName, JSON.stringify(receiptData));
          console.log("Receipt Downloaded successfully.....");
  }
  else{
      console.log('Signature not valid from client');
  }


      /*
      let user_public_key = forge.pki.publicKeyFromPem(message_data.public_key);
      let user_signed_message = message_data.signed_Data;
      let consent_details = {
        htmlContent: htmlContent,
        javascript: allJavascriptContent,
        policy: allPolicyContent,
        PII: message_data.PII,
        timestamp: message_data.timestamp,
        nounce: message_data.nounce,
      };
      console.log("Got all details from client");
      let messageDigest = forge.md.sha256.create();
      messageDigest.update(consent_details, "utf8");
      let verify = user_public_key.verify(
        messageDigest.digest().bytes(),
        user_signed_message
      );
      // If the signature is valid then
      if (verify) {
        console.log("Signature Verified");
        console.log("Downloading");
        let receiptData = {
          version: 1,
          user_public_key: message_data.public_key,
          signed_Messaged: message_data.signed_Data,
          PII: message_data.PII,
          html: htmlContent,
          javascript: allJavascriptContent,
          policy: allPolicyContent,
          policyHash: policyHash,
        };
        let fileName = `receipts/receipt${Date.now()}.json`;
        fs.writeFileSync(fileName, JSON.stringify(receiptData));
        console.log("Receipt Downloaded");
      } else {
        console.log("Signature not valid from client");
      }
      */
    }

    if (message.title == "getSignedMessage") {
      let timestamp = new Date().getTime();
      let nounce = (1e9 * Math.random() * 1e9 * Math.random()).toString(16);
      let consent_details = {
        htmlContent: htmlContent,
        javascript: allJavascriptContent,
        policy: allPolicyContent,
        PII: message_data.PII,
        timestamp: timestamp,
        nounce: nounce,
      };

      let rc = forge.md.sha256.create();
      rc.update(consent_details, "utf8");
      let sigedMessaged = privateKey.sign(rc);
      console.log(">>>>>>Data Signed By the Server<<<<<<<<");
      let data = {
        signedMessage: sigedMessaged,
        server_publickeypem: publicKey_pem,
        timestamp: timestamp,
        nounce: nounce,
      };
      console.log("Sending Signed Data To the Client");
      ws.send(
        JSON.stringify({ title: "signedMessageFromConsentGateWay", data: data })
      );
    }
  });

  ws.on("close", () => {
    console.log("Connection Closed with the client");
  });
});

/*
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
*/
//functions
async function getHtml(url) {
  htmlContent = await getContentFromUrl(url);
}

async function getJavaScriptCode(allFiles) {
  allJavascriptContent = "";
  if (allFiles.length > 0) {
    for (let thiscript of allFiles) {
      if (thiscript.src != "") {
        let javascriptCode = await getContentFromUrl(thiscript.src);
        allJavascriptContent += javascriptCode;
      } else {
        allJavascriptContent += thiscript.innerHTML;
      }
    }
  }
}

async function generateHash() {
  htmlHash = await sha256(htmlContent);
  policyHash = await sha256(allPolicyContent);
  javascriptHash = await sha256(allJavascriptContent);
}

async function generateHashcompliant() {
  htmlHash = await sha256(htmlContent);
  policyHash = await sha256(allPolicyContent);
  javascriptHash = await sha256(allJavascriptContent);
}

async function getContentFromUrl(file) {
  var res = await fetch(file);
  res = await res.text();
  return res.toString(16);
}

async function gatherPolicyFiles(policyUrls) {
  allPolicyContent = "";
  if (policyUrls.length > 0) {
    for (let policyUrl of policyUrls) {
      let policyUrlContent = await getContentFromUrl(policyUrl);
      allPolicyContent += policyUrlContent;
    }
  }
}

async function gatherJavascriptFiles(javascriptUrls) {
  allJavascriptContent = "";

  for (let javascripturl of javascriptUrls) {
    let javasciptcode = await getContentFromUrl(javascripturl);
    allJavascriptContent += javasciptcode;
  }
}
