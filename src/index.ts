import * as bitcoin from "bitcoinjs-lib";
import { EventEmitter } from "events";
import ECPairFactory, { ECPairInterface } from "ecpair";
import * as ecc from "tiny-secp256k1";
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
import { decode } from "bs58check";
const type = "Simple Key Pair";
export const toXOnly = (pubKey: Buffer) =>
  pubKey.length === 32 ? pubKey : pubKey.slice(1, 33);

function tapTweakHash(pubKey: Buffer, h: Buffer | undefined): Buffer {
  return bitcoin.crypto.taggedHash(
    "TapTweak",
    Buffer.concat(h ? [pubKey, h] : [pubKey])
  );
}

function tweakSigner(signer: bitcoin.Signer, opts: any = {}): bitcoin.Signer {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  let privateKey: Uint8Array | undefined = signer.privateKey!;
  if (!privateKey) {
    throw new Error("Private key is required for tweaking signer!");
  }
  if (signer.publicKey[0] === 3) {
    privateKey = ecc.privateNegate(privateKey);
  }

  const tweakedPrivateKey = ecc.privateAdd(
    privateKey,
    tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash)
  );
  if (!tweakedPrivateKey) {
    throw new Error("Invalid tweaked private key!");
  }

  return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
    network: opts.network,
  });
}

enum AddressType {
  P2PKH,
  P2WPKH,
  P2TR,
}

export class SimpleKeyring extends EventEmitter {
  static type = type;
  type = type;
  network: bitcoin.Network = bitcoin.networks.bitcoin;
  wallets: ECPairInterface[] = [];
  constructor(opts?: any) {
    super();
    if (opts) {
      this.deserialize(opts);
    }
  }

  async serialize(): Promise<any> {
    return this.wallets.map((wallet) => wallet.privateKey.toString("hex"));
  }

  async deserialize(opts: any) {
    const privateKeys = opts as string[];

    this.wallets = privateKeys.map((key) => {
      let buf: Buffer;
      if (key.length === 64) {
        // privateKey
        buf = Buffer.from(key, "hex");
      } else {
        // base58
        buf = decode(key).slice(1, 33);
      }

      return ECPair.fromPrivateKey(buf);
    });
  }

  async addAccounts(n = 1) {
    const newWallets: ECPairInterface[] = [];
    for (let i = 0; i < n; i++) {
      newWallets.push(
        ECPair.makeRandom({
          network: this.network,
        })
      );
    }
    this.wallets = this.wallets.concat(newWallets);
    const hexWallets = newWallets.map(({ publicKey }) =>
      publicKey.toString("hex")
    );
    return hexWallets;
  }

  async getAccounts() {
    return this.wallets.map(({ publicKey }) => publicKey.toString("hex"));
  }

  async signTransaction(
    psbt: bitcoin.Psbt,
    inputs: { index: number; publicKey: string; type: AddressType }[]
  ) {
    inputs.forEach((input) => {
      const keyPair = this._getPrivateKeyFor(input.publicKey);

      if (input.type == AddressType.P2TR) {
        const signer = tweakSigner(keyPair, {
          network: keyPair.network,
        });
        psbt.signInput(input.index, signer);
      } else {
        const signer = keyPair;
        psbt.signInput(input.index, signer);
      }
    });
  }

  private _getPrivateKeyFor(publicKey: string) {
    if (!publicKey) {
      throw new Error("Must specify publicKey.");
    }
    const wallet = this._getWalletForAccount(publicKey);
    return wallet;
  }

  async exportAccount(publicKey: string) {
    const wallet = this._getWalletForAccount(publicKey);
    return wallet.privateKey.toString("hex");
  }

  removeAccount(publicKey: string) {
    if (
      !this.wallets
        .map((wallet) => wallet.publicKey.toString("hex"))
        .includes(publicKey)
    ) {
      throw new Error(`PublicKey ${publicKey} not found in this keyring`);
    }

    this.wallets = this.wallets.filter(
      (wallet) => wallet.publicKey.toString("hex") !== publicKey
    );
  }

  private _getWalletForAccount(publicKey: string) {
    let wallet = this.wallets.find(
      (wallet) => wallet.publicKey.toString("hex") == publicKey
    );
    if (!wallet) {
      throw new Error("Simple Keyring - Unable to find matching publicKey.");
    }
    return wallet;
  }
}
