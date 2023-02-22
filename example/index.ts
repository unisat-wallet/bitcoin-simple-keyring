import { SimpleKeyring } from "../";
const run = async () => {
  const keyring = new SimpleKeyring();
  const accounts = await keyring.addAccounts(3);
  const privateKeys = await keyring.serialize();
  console.log("accounts:", accounts);
  console.log("privateKeys:", privateKeys);
};

run();
