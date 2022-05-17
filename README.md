# hedera-aws-kms-signing

This repo contains the code to demonstrate how to use AWS KMS to sign transactions for Hedera Network.

## Prerequisite

1. AWS account with access key id and secret key - please check out this [link](https://aws.amazon.com/premiumsupport/knowledge-center/create-access-key/) to learn how to create access key id and secret key.
2. Set up KMS on AWS - create a new key with key type `Asymmetric`, key usage `Sign and verify`, and key spec `ECC_SECG_P256K1` on AWS KMS. Please make sure you give the KMS access permission to the new access key id and secret key you just created at step one.
3. Hedera test account - if you don't have an account, please check out [portal](https://portal.hedera.com/register/) and register to get one.

## Install

```bash
npm install
```

## Run

You need to specify the environment variables in .env before you can run the code. All environment variables are required

```bash
mv .env_sample .env
node index.js
```

if the code run successfully, you should see something similar to the following messages

```
Creating a new account
The new account ID is: 0.0.34827198
0.0.34827198 balance:  0.002 ℏ
Signing transaction in transactionSigner
Signing transaction in transactionSigner
Signing transaction in transactionSigner
Signing transaction in transactionSigner
The transfer transaction from my account to the new account was: SUCCESS
Check transaction here: https://hashscan.io/#/testnet/transaction/0.0.34827198-1652759412-391672572
Done
```
