import {
  BIP44HDPath,
  CommonCrypto,
  KeyRing,
  LedgerService,
  ScryptParams,
} from '@keplr-wallet/background';
import { MemoryKVStore } from '@keplr-wallet/common';
import { Env } from '@keplr-wallet/router';
import scrypt from 'scrypt-js';
import { serializeSignDoc } from '@cosmjs/launchpad';
import { EmbedChainInfos } from './config';

// export type FnRequestInteraction = <M extends Message<unknown>>(
//   url: string,
//   msg: M,
//   options?: FnRequestInteractionOptions
// ) => Promise<M extends Message<infer R> ? R : never>;

const chainId = 'cosmoshub-4';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const crypto = require('crypto').webcrypto;

// const env = ExtensionEnv.produceEnv(
//   { id: 'id', url: 'https://point', tab: '1' },
//   {}
// );

const env = {
  isInternalMsg: true,
  requestInteraction: async () => true,
};
// (
//   url: string,
//   msg: M,
//   options?: FnRequestInteractionOptions
// ) => Promise<M extends Message<infer R> ? R : never>;
// }

const keyRing = new KeyRing(
  EmbedChainInfos,
  new MemoryKVStore('test'),
  new LedgerService(new MemoryKVStore('ledger'), {}),
  {
    rng: (array) => Promise.resolve(crypto.getRandomValues(array)),
    scrypt: async (text: string, params: ScryptParams) =>
      scrypt.scrypt(
        Buffer.from(text),
        Buffer.from(params.salt, 'hex'),
        params.n,
        params.r,
        params.p,
        params.dklen
      ),
  }
);

async function main() {
  console.log('*1');
  await keyRing.restore();
  console.log('*2');
  await keyRing.createMnemonicKey(
    'sha256',
    'supply label curve utility satisfy wet alley about soda goddess useless frequent',
    '1234',
    {},
    { account: 0, change: 0, addressIndex: 0 } // is this BIP44HDPath ok?
  );
  // await keyRing.unlock('1');
  console.log('*2.5');
  // await keyRing.addMnemonicKey(
  //   'sha256',
  //   'supply label curve utility satisfy wet alley about soda goddess useless frequent',
  //   {},
  //   { account: 0, change: 0, addressIndex: 0 } // is this BIP44HDPath ok?
  // );
  console.log('*3');
  const coinType = 118;
  const key = keyRing.getKey(chainId, coinType, false);
  console.log('*4');
  console.log({ key });
  const signature = await keyRing.sign(
    env as Env,
    chainId,
    coinType,
    serializeSignDoc({
      fee: {
        gas: '1',
        amount: [{ denom: 'point', amount: '1' }],
      },
      chain_id: chainId,
      account_number: '1',
      sequence: '1',
      msgs: [],
      memo: 'memoo',
    }),
    false
  );

  console.log({ signature });

  // return {
  //   signed: newSignDoc,
  //   signature: encodeSecp256k1Signature(key.pubKey, signature),
  // };

  // export interface Env {
  //   readonly isInternalMsg: boolean;
  //   readonly requestInteraction: FnRequestInteraction;
  // }

  // export type FnRequestInteraction = <M extends Message<unknown>>(
  //   url: string,
  //   msg: M,
  //   options?: FnRequestInteractionOptions
  // ) => Promise<M extends Message<infer R> ? R : never>;
}

main();
