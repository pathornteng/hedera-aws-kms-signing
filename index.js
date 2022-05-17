const elliptic = require("elliptic");
const ec = new elliptic.ec("secp256k1");
const keccak256 = require("keccak256");
const asn1 = require("asn1.js");
const {
  Client,
  Hbar,
  AccountCreateTransaction,
  PublicKey,
  AccountBalanceQuery,
  TransferTransaction,
} = require("@hashgraph/sdk");
const {
  KMSClient,
  SignCommand,
  GetPublicKeyCommand,
} = require("@aws-sdk/client-kms");
const dotenv = require("dotenv");
dotenv.config();

const kmsClient = new KMSClient({
  credentials: {
    // Credentials for your IAM user with KMS access
    accessKeyId: process.env.AWS_KMS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_KMS_SECRET_ACCESSS_KEY,
  },
  region: process.env.AWS_KMS_REGION,
});
const signingInput = {
  // AWS KMS Key ID
  KeyId: process.env.AWS_KMS_KEY_ID,
  // Signing algorithm
  SigningAlgorithm: "ECDSA_SHA_256",
  MessageType: "DIGEST",
};

const EcdsaSigAsnParse = asn1.define("EcdsaSig", function () {
  // Parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

async function transactionSigner(bytesToSign) {
  console.log("Signing transaction in transactionSigner");
  // Create keccak256 message digest
  const dataHex = Buffer.from(bytesToSign).toString("hex");
  const hash = keccak256(`0x${dataHex}`);

  // Send digest to KMS for signing
  signingInput.Message = hash;
  const command = new SignCommand(signingInput);
  const response = await kmsClient.send(command);

  // Construct ECDSA signature
  let decoded = EcdsaSigAsnParse.decode(Buffer.from(response.Signature), "der");
  let r = decoded.r.toArray("be", 32);
  let s = decoded.s.toArray("be", 32);
  const result = new Uint8Array(64);
  result.set(r, 0);
  result.set(s, 32);
  return result;
}

async function createAccountWith(publicKey) {
  console.log("Creating a new account");
  // Create our connection to the Hedera network
  // Use another key to create a new account with KMS public key
  const myAccountId = process.env.HEDERA_ACCOUNT_ID;
  const myPrivateKey = process.env.HEDERA_PRIVATE_KEY;

  // If we weren't able to grab it, we should throw a new error
  if (myAccountId == null || myPrivateKey == null) {
    throw new Error(
      "Environment variables myAccountId and myPrivateKey must be present"
    );
  }
  // The Hedera JS SDK makes this really easy!
  const client = Client.forTestnet();
  client.setOperator(myAccountId, myPrivateKey);
  // Create a new account with 200,000 tinybar starting balance
  const newAccount = await new AccountCreateTransaction()
    .setKey(publicKey)
    .setInitialBalance(Hbar.fromTinybars(200000))
    .execute(client);

  // Get the new account ID
  const getReceipt = await newAccount.getReceipt(client);
  const newAccountId = getReceipt.accountId;

  console.log("The new account ID is: " + newAccountId);
  return newAccountId;
}

const main = async () => {
  // Fetch public key from AWS KMS
  const publicCommand = new GetPublicKeyCommand({
    KeyId: process.env.AWS_KMS_KEY_ID,
  });
  const publicResponse = await kmsClient.send(publicCommand);
  let hexPublicKey = Buffer.from(publicResponse.PublicKey).toString("hex");
  // Remove public key prefix
  hexPublicKey = hexPublicKey.replace(
    "3056301006072a8648ce3d020106052b8104000a034200",
    ""
  );
  // Instantiate public key objects
  let kmsPublicKey = ec.keyFromPublic(hexPublicKey, "hex");
  const newAccountPublicKey = PublicKey.fromBytesECDSA(
    Buffer.from(kmsPublicKey.getPublic().encodeCompressed("hex"), "hex")
  );

  // Create a new acccount associated with kms public key
  const newAccountId = await createAccountWith(newAccountPublicKey);
  const client = Client.forTestnet();
  client.setOperatorWith(newAccountId, newAccountPublicKey, transactionSigner);

  // Query initial balance
  let accountBalance = await new AccountBalanceQuery()
    .setAccountId(newAccountId)
    .execute(client);
  console.log(`${newAccountId} balance: `, accountBalance.hbars.toString());

  // Send Hbar to account 0.0.3
  const sendHbar = await new TransferTransaction()
    .addHbarTransfer(newAccountId, Hbar.fromTinybars(-10000)) //Sending account
    .addHbarTransfer("0.0.3", Hbar.fromTinybars(10000)) //Receiving account
    .execute(client);
  const transactionReceipt = await sendHbar.getReceipt(client);
  console.log(
    "The transfer transaction from my account to the new account was: " +
      transactionReceipt.status.toString()
  );
  let transactionId = sendHbar.transactionId.toString();
  transactionId = transactionId
    .replace("@", "-")
    .replace(/\./g, "-")
    .replace(/0-/g, "0.");
  console.log(
    "Check transaction here: https://hashscan.io/#/testnet/transaction/" +
      transactionId
  );
  console.log("Done");
};

main();
