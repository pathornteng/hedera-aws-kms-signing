import keccak256 from "keccak256";
import {
  Client,
  Hbar,
  AccountCreateTransaction,
  PublicKey,
  AccountBalanceQuery,
  TransferTransaction,
  Key,
  AccountId,
  PrivateKey,
  HbarUnit,
} from "@hashgraph/sdk";
import {
  KMSClient,
  SignCommand,
  GetPublicKeyCommand,
  type SignCommandInput,
} from "@aws-sdk/client-kms";
import EcdsaAsn1Signature from "./EcdsaAsn1Signature";
import dotenv from "dotenv";
dotenv.config();

const SINGING_ALGORITHM = "ECDSA_SHA_256";
const MESSAGE_TYPE = "DIGEST";

let kmsClient: KMSClient;

/**
 * Signer function for Hedera Client. Signs a transaction by sending the digest to AWS KMS for signing.
 *
 * @param bytesToSign - The bytes to sign.
 * @returns The raw ECDSA signature.
 * @throws Error if the AWS KMS Key ID is not present in the environment variables or if the signature is not found.
 */
async function transactionSigner(bytesToSign: Uint8Array) {
  console.info("Signing transaction in transactionSigner");
  // Get AWS KMS Key ID from environment variables (it cannot be a function parameter)
  const awsKmsKeyId = process.env.AWS_KMS_KEY_ID;
  if (!awsKmsKeyId) {
    throw new Error("Environment variable AWS_KMS_KEY_ID must be present");
  }
  // Create keccak256 | SHA3 message digest
  const hash = keccak256(Buffer.from(bytesToSign));

  // Send digest to KMS for signing
  const signCommandInput = {
    Message: hash,
    KeyId: awsKmsKeyId,
    SigningAlgorithm: SINGING_ALGORITHM,
    MessageType: MESSAGE_TYPE,
  } as SignCommandInput;
  const command = new SignCommand(signCommandInput);
  const response = await kmsClient.send(command);
  console.log(`RAW response: ${JSON.stringify(response)}`);
  if (!response.Signature) {
    throw new Error("Signature not found");
  }

  // Parse the DER encoded signature to get the raw ECDSA signature
  const ecdsaSignature = EcdsaAsn1Signature.fromDER(Buffer.from(response.Signature));
  // -- Concatenate the r and s values of the signature and remove the leading 0x00 byte if present
  const rawSignature = Buffer.concat([
    ecdsaSignature.r[0] == 0 ? ecdsaSignature.r.slice(1) : ecdsaSignature.r,
    ecdsaSignature.s[0] == 0 ? ecdsaSignature.s.slice(1) : ecdsaSignature.s,
  ]);

  return new Uint8Array(rawSignature);
}

async function createAccountWith(
  publicKey: Key,
  operator: { accountId: AccountId | string; privateKey: PrivateKey | string }
) {
  console.log(`Creating a new account with public key: ${publicKey.toString()}`);
  // Create our connection to the Hedera network
  const client = Client.forTestnet();
  client.setOperator(operator.accountId, operator.privateKey);
  // Create a new account with 200,000 tinybar starting balance
  const newAccount = await new AccountCreateTransaction()
    .setKey(publicKey) // The public key of the new account
    .setInitialBalance(Hbar.from(0.1, HbarUnit.Hbar)) // 0.1 hbar
    .execute(client); // Submit the transaction to the network with a previous account ID and its private key

  // Get the new account ID
  const getReceipt = await newAccount.getReceipt(client);
  const newAccountId = getReceipt.accountId;
  if (!newAccountId) {
    throw new Error("New account ID was null");
  }

  console.log("The new account ID is: " + newAccountId);
  return newAccountId;
}

/**
 * Retrieves the AWS public key associated with the specified key ID.
 *
 * @param keyId - The ID of the key.
 * @returns A promise that resolves to the PublicKey object representing the AWS public key.
 * @throws An error if the AWS public key is not found.
 */
async function getAwsPublicKey({ keyId }: { keyId: string }): Promise<PublicKey> {
  const publicCommand = new GetPublicKeyCommand({
    KeyId: keyId,
  });
  const publicResponse = await kmsClient.send(publicCommand);
  if (!publicResponse.PublicKey) {
    throw new Error("AWS Public key not found");
  }
  return PublicKey.fromBytes(publicResponse.PublicKey);
}

const main = async () => {
  // Get Environment Variables
  const awsAccessKeyId = process.env.AWS_KMS_ACCESS_KEY_ID;
  const awsSecretAccessKey = process.env.AWS_KMS_SECRET_ACCESS_KEY;
  const awsRegion = process.env.AWS_KMS_REGION;
  const awsKmsKeyId = process.env.AWS_KMS_KEY_ID;
  const previousAccountId = process.env.HEDERA_ACCOUNT_ID;
  const previousPrivateKey = process.env.HEDERA_PRIVATE_KEY;

  // If any of the required environment variables are missing, throw an error
  if (
    !awsAccessKeyId ||
    !awsSecretAccessKey ||
    !awsRegion ||
    !awsKmsKeyId ||
    !previousAccountId ||
    !previousPrivateKey
  ) {
    throw new Error(
      "Environment variables awsAccessKeyId, awsSecretAccessKey, awsRegion, awsKmsKeyId, previousAccountId, and previousPrivateKey must be present"
    );
  }

  // Create an AWS KMS client
  kmsClient = new KMSClient({
    region: awsRegion,
    credentials: {
      accessKeyId: awsAccessKeyId,
      secretAccessKey: awsSecretAccessKey,
    },
  });

  // Fetch public key from AWS KMS
  const awsPublicKey = await getAwsPublicKey({ keyId: awsKmsKeyId });

  // Create a new acccount associated with AWS KMS public key
  const newAccountId = await createAccountWith(awsPublicKey, {
    accountId: AccountId.fromString(previousAccountId),
    privateKey: PrivateKey.fromStringDer(previousPrivateKey),
  });

  // Create a new Hedera client with the new account and add Signing function
  const client = Client.forTestnet().setOperatorWith(newAccountId, awsPublicKey, transactionSigner);

  // Query initial balance
  let accountBalance = await new AccountBalanceQuery().setAccountId(newAccountId).execute(client);
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
  transactionId = transactionId.replace("@", "-").replace(/\./g, "-").replace(/0-/g, "0.");
  console.log("Check transaction here: https://hashscan.io/#/testnet/transaction/" + transactionId);
  console.log("Done");
};

main()
  .catch(console.error)
  .finally(() => process.exit());
