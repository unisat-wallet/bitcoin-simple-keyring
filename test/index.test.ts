import * as bitcoin from "bitcoinjs-lib";
import { expect } from "chai";
import { SimpleKeyring } from "../src";

const TYPE_STR = "Simple Key Pair";

const testAccount = {
  key: "88544d58a328a380a4a433e4bb44b2a9f8a1152b1467393cfc8f8e5d81137162",
  address: "02b57a152325231723ee9faabba930108b19c11a391751572f380d71b447317ae7",
};

describe("bitcoin-simple-keyring", () => {
  let keyring: SimpleKeyring;
  beforeEach(() => {
    keyring = new SimpleKeyring();
  });

  describe("Keyring.type", function () {
    it("is a class property that returns the type string.", function () {
      const { type } = SimpleKeyring;
      expect(type).eq(TYPE_STR);
    });
  });

  describe("#serialize empty wallets.", function () {
    it("serializes an empty array", async function () {
      const output = await keyring.serialize();
      expect(output.length == 0).to.be.true;
    });
  });

  describe("#deserialize a private key", function () {
    it("serializes what it deserializes", async function () {
      await keyring.deserialize([testAccount.key]);
      const serialized = await keyring.serialize();
      expect(serialized).length(1);
      expect(serialized[0]).eq(testAccount.key);
    });
  });

  describe("#constructor with a private key", function () {
    it("has the correct addresses", async function () {
      const newKeyring = new SimpleKeyring([testAccount.key]);
      const accounts = await newKeyring.getAccounts();
      expect(accounts).eqls([testAccount.address]);
    });
  });

  describe("#add accounts", function () {
    describe("with no arguments", function () {
      it("creates a single wallet", async function () {
        await keyring.addAccounts();
        const serializedKeyring = await keyring.serialize();
        expect(serializedKeyring).length(1);
      });
    });

    describe("with a numeric argument", function () {
      it("creates that number of wallets", async function () {
        await keyring.addAccounts(3);
        const serializedKeyring = await keyring.serialize();
        expect(serializedKeyring).length(3);
      });
    });

    describe("#getAccounts", function () {
      it("should return a list of addresses in wallet", async function () {
        // Push a mock wallet
        keyring.deserialize([testAccount.key]);

        const output = await keyring.getAccounts();
        expect(output).length(1);
        expect(output[0]).eql(testAccount.address);
      });
    });

    describe("#removeAccount", function () {
      describe("if the account exists", function () {
        it("should remove that account", async function () {
          await keyring.addAccounts();
          const addresses = await keyring.getAccounts();
          expect(addresses).length(1);
          keyring.removeAccount(addresses[0]);
          const addressesAfterRemoval = await keyring.getAccounts();
          expect(addressesAfterRemoval).length(0);
        });
      });

      describe("if the account does not exist", function () {
        it("should throw an error", function () {
          const unexistingAccount =
            "000000000000000000000000000000000000000000000000000000000000000000";
          expect(() => keyring.removeAccount(unexistingAccount)).throw(
            `PublicKey ${unexistingAccount} not found in this keyring`
          );
        });
      });
    });
  });

  describe("#sign message", function () {
    it("verify sig success", async function () {
      const newKeyring = new SimpleKeyring([testAccount.key]);
      const accounts = await newKeyring.getAccounts();
      const pubkey = accounts[0];
      const msg = "HELLO WORLD";
      const sig = await newKeyring.signMessage(pubkey, msg);
      const verified = await newKeyring.verifyMessage(pubkey, msg, sig);
      expect(verified).eq(true);
    });
  });

});
