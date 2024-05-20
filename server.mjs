import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto"; // For SHA256
import { decode, encode } from "cborg";
// import sha256 from "crypto-js/sha256";
import sha256 from "sha256";
import { stringify } from "uuid";
import * as base58 from "base58-universal";
import queryString from "querystring";
import { createServer } from "node:http";
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { fileURLToPath } from "url"; // Import fileURLToPath
import path from "path"; // Import the path module
import https from "https";
import fs from "fs";

const port = 3001;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename); // Assuming you imported path

const options = {
  key: fs.readFileSync("/etc/letsencrypt/live/appheaven.us/privkey.pem"),
  cert: fs.readFileSync("/etc/letsencrypt/live/appheaven.us/cert.pem"),
};

// Replace with your actual environment variables
const envAccessKey = "Kz3wG6vR1J2Pq8Lx9Bn4Cm5D";
const envSecretKey = "Yt6FpN2mH8sZx5Vr9Qb4Kj3L";

// Function to convert timestamp to RFC3339 datetime format
function convertToRfc3339Datetime(data) {
  const datetime = new Date(data * 1000);
  return datetime.toISOString().slice(0, -5) + "Z";
}

// Function to convert DID data to DID format
function convertToDid(data) {
  const scheme = data[0];
  const authority = data[1];
  const fragment = data[2] || null;
  if (scheme !== 1025) {
    console.error("error: malformed DID encoding", data);
    return null;
  }

  const did = fragment
    ? `did:key:<span class="math-inline">\{encodeMultibasePublicKey\(authority\)\}\#</span>{encodeMultibasePublicKey(fragment)}`
    : `did:key:${encodeMultibasePublicKey(authority)}`;

  return did;
}

// Helper function to encode the bytes of a multicodec key to a multibase base58 string
function encodeMultibasePublicKey(multicodecKeyBytes) {
  const MULTIBASE_BASE58BTC_HEADER = "z";
  return MULTIBASE_BASE58BTC_HEADER + base58.encode(multicodecKeyBytes);
}

async function sha256Function(buf) {
  // Assuming 'buf' is a buffer or string
  const hashHex = sha256(buf).toString();

  // Convert the hexadecimal hash to a Uint8Array
  const hashBytes = new Uint8Array(
    hashHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
  );

  return hashBytes;
}

// Function to convert data to multibase format
function _convertToMultibase(data) {
  const encoding = data[0];
  const bytes = data.slice(1);
  if (encoding !== 0x7a) {
    console.error("error: unknown multibase encoding", data);
    return null;
  }
  return "z" + base58.encode(bytes);
}

// // Verification logic (replace with your specific verification process)
// async function verifySignature(QRString) {
//   // Helper function to convert bytes to UUID format
//   function convertToUuid(data) {
//     const type = data[0];
//     const bytes = data[1];
//     console.dir(bytes);
//     console.dir("llll");
//     console.dir(stringify(bytes));
//     if (type !== 3) {
//       console.log("error: malformed UUID encoding", data);
//     }

//     return "urn:uuid:" + stringify(bytes);
//   }
// }

function base32Decode(input) {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // RFC 4648
  const OUTPUT_BITS = 5;
  const output = [];
  let buffer = 0;
  let next = 0;

  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    const charValue = ALPHABET.indexOf(char);
    if (charValue === -1) {
      throw new Error("Invalid base32 character");
    }
    buffer |= charValue;
    next += OUTPUT_BITS;
    if (next >= 8) {
      output.push((buffer >>> (next - 8)) & 0xff);
      next -= 8;
    }
    buffer <<= OUTPUT_BITS;
  }

  // Pad the last byte if necessary
  if (next > 0) {
    output.push((buffer << (OUTPUT_BITS - next)) & 0xff);
  }

  return new Uint8Array(output);
}

// Verification logic (replace with your specific verification process)
async function verifySignature(QRString) {
  // Helper function to convert bytes to UUID format
  function convertToUuid(data) {
    const type = data[0];
    const bytes = data[1];
    console.dir(bytes);
    console.dir("llll");
    console.dir(stringify(bytes));
    if (type !== 3) {
      console.log("error: malformed UUID encoding", data);
    }

    return "urn:uuid:" + stringify(bytes);
  }

  // ... rest of the verification logic ...
}

const app = express();
app.use(bodyParser.urlencoded({ extended: true })); // Parse incoming POST data

app.use("/verification", async (req, res) => {
  console.log(`Pinged`);

  const responseData = {};

  try {
    // Access request body data
    const { accessKey, secretKey, QRString } = req.body;

    console.log("accessKey:", accessKey);
    console.log("secretKey:", secretKey);
    console.log("QRString:", QRString);

    // Check for required data
    if (!accessKey || !secretKey || !QRString) {
      responseData.success = false;
      responseData.message = "Missing field(s)";
      res.status(400).json(responseData);
      return;
    }

    // Authentication check
    if (accessKey !== envAccessKey || secretKey !== envSecretKey) {
      responseData.success = false;
      responseData.message = "Authentication Failed";
      res.status(401).json(responseData);
      return;
    }

    // Get the base32 encoded credential from the QR code string
    const base32EncodedCredential = QRString.slice(5);

    // Base32 (RFC4648 Uppercase, no padding) decode the resulting string
    const cborArrayBuffer = base32Decode(base32EncodedCredential);

    // Chop off the first 3 bytes
    const cborBytes = new Uint8Array(cborArrayBuffer.slice(3));

    // Decode the CBOR-encoded credential bytes into a CBOR Map data structure
    const cborMap = decode(cborBytes, { useMaps: true });

    // ... rest of the verification logic using the decoded CBOR data ...
  } catch (error) {
    console.error("Error:", error);
    responseData.success = false;
    responseData.message = "Verification Failed";
    res.status(500).json(responseData);
  }
});

// Serve static files from the 'build' folder of the React app
app.use(express.static(path.join(__dirname, "build")));

// All other routes should redirect to the React app's index.html
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "build", "index.html"));
});

const server = https.createServer(options, app);

server.listen(port, "0.0.0.0", () => {
  console.log(`Server running at port :${port}`);
});
