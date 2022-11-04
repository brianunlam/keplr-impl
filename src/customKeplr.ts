/* eslint-disable no-param-reassign */
/* eslint-disable default-case */
/* eslint-disable @typescript-eslint/no-shadow */
// eslint-disable-next-line @typescript-eslint/no-var-requires
import { ChainInfo, EthSignType, KeplrSignOptions } from '@keplr-wallet/types';
import { Wallet } from '@ethersproject/wallet';
import { SignDoc } from '@keplr-wallet/proto-types/cosmos/tx/v1beta1/tx';
import { DirectSignResponse, makeSignBytes } from '@cosmjs/proto-signing';

import {
  AminoSignResponse,
  StdSignDoc,
  encodeSecp256k1Signature,
  encodeSecp256k1Pubkey,
  serializeSignDoc,
} from '@cosmjs/launchpad';

import Long from 'long';
import { EmbedChainInfos } from './config';
import { PrivKeySecp256k1 } from './key';
import { Bech32Address } from './bech32address';
import { checkAndValidateADR36AminoSignDoc } from './amino';
import { trimAminoSignDoc } from './amino-sign-doc';
import { sortObjectByKey } from './sortObjectByKey';
import { signEthereum } from './signEthereum';
import { sign } from './sign';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const bip39 = require('bip39');
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bip32 = require('bip32');
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bs58check = require('bs58check');

export interface Key {
  algo: string;
  pubKey: Uint8Array;
  address: Uint8Array;
  isNanoLedger: boolean;
}

export class KeplrError extends Error {
  public readonly module: string;

  public readonly code: number;

  constructor(module: string, code: number, message?: string) {
    super(message);
    this.module = module;
    this.code = code;

    Object.setPrototypeOf(this, KeplrError.prototype);
  }
}

const VersionFormatRegExp = /(.+)-([\d]+)/;

export function parseChainId(chainId: string): {
  identifier: string;
  version: number;
} {
  const split = chainId.split(VersionFormatRegExp).filter(Boolean);
  if (split.length !== 2) {
    return {
      identifier: chainId,
      version: 0,
    };
  }
  return { identifier: split[0], version: parseInt(split[1], 10) };
}

export function parseEthermintChainId(chainId: string): {
  identifier: string;
  version: number;

  ethChainId: number;
} {
  const matches = chainId.match(
    '^([a-z]{1,})_{1}([1-9][0-9]*)-{1}([1-9][0-9]*)$'
  );

  if (
    !matches ||
    matches.length !== 4 ||
    matches[1] === '' ||
    Number.isNaN(parseFloat(matches[2])) ||
    !Number.isInteger(parseFloat(matches[2]))
  ) {
    throw new Error(`Invalid chainId for ethermint: ${chainId}`);
  }

  const cosmosChainId = parseChainId(chainId);

  return {
    ...cosmosChainId,
    ethChainId: parseFloat(matches[2]),
  };
}

export function createChainsService() {
  const chainsService = {
    getChainInfo(chainId: string): ChainInfo | undefined {
      return EmbedChainInfos.find((chainInfo) => {
        return (
          parseChainId(chainInfo.chainId).identifier ===
          parseChainId(chainId).identifier
        );
      });
    },
    getChainEthereumKeyFeatures(chainId: string): {
      address: boolean;
      signing: boolean;
    } {
      const chainInfo = chainsService.getChainInfo(chainId);
      return {
        address: chainInfo?.features?.includes('eth-address-gen') ?? false,
        signing: chainInfo?.features?.includes('eth-key-sign') ?? false,
      };
    },
    getChainCoinType(chainId: string): number {
      const chainInfo = chainsService.getChainInfo(chainId);

      if (!chainInfo) {
        throw new KeplrError(
          'chains',
          411,
          `There is no chain info for ${chainId}`
        );
      }

      return chainInfo.bip44.coinType;
    },
  };
  return chainsService;
}

export function generateMasterSeedFromMnemonic(
  mnemonic: string,
  password = ''
): Uint8Array {
  console.log({ mnemonic, password });
  const seed = bip39.mnemonicToSeedSync(mnemonic, password);
  const masterKey = bip32.fromSeed(seed);
  console.log('--------inside generateMasterSeedFromMnemonic');
  console.log({ seed, masterKey });
  return Buffer.from(bs58check.decode(masterKey.toBase58()));
}

export function generatePrivateKeyFromMasterSeed(
  seed: Uint8Array,
  // eslint-disable-next-line quotes
  path = "m/44'/118'/0'/0/0"
): Uint8Array {
  const masterSeed = bip32.fromBase58(bs58check.encode(seed));
  const hd = masterSeed.derivePath(path);

  const { privateKey } = hd;
  if (!privateKey) {
    throw new Error('null hd key');
  }
  return privateKey;
}

export function validateSignAmino(
  chainId: string,
  signer: string,
  signDoc: StdSignDoc,
  signOptions: KeplrSignOptions & {
    // Hack option field to detect the sign arbitrary for string
    isADR36WithString?: boolean;
    ethSignType?: EthSignType;
  } = {}
) {
  if (!chainId) {
    throw new KeplrError('keyring', 270, 'chain id not set');
  }

  if (!signer) {
    throw new KeplrError('keyring', 230, 'signer not set');
  }

  // Validate bech32 address.
  Bech32Address.validate(signer);

  // Check and validate the ADR-36 sign doc.
  // ADR-36 sign doc doesn't have the chain id
  if (!checkAndValidateADR36AminoSignDoc(signDoc)) {
    if (signOptions.ethSignType) {
      throw new Error(
        'Eth sign type can be requested with only ADR-36 amino sign doc'
      );
    }

    if (signDoc.chain_id !== chainId) {
      throw new KeplrError(
        'keyring',
        234,
        'Chain id in the message is not matched with the requested chain id'
      );
    }
  } else {
    if (signDoc.msgs[0].value.signer !== signer) {
      throw new KeplrError('keyring', 233, 'Unmatched signer in sign doc');
    }

    if (signOptions.ethSignType) {
      switch (signOptions.ethSignType) {
        // TODO: Check chain id in tx data.
        // case EthSignType.TRANSACTION:
        case EthSignType.EIP712: {
          const message = JSON.parse(
            Buffer.from(signDoc.msgs[0].value.data, 'base64').toString()
          );
          const { ethChainId } = parseEthermintChainId(chainId);
          if (parseFloat(message.domain?.chainId) !== ethChainId) {
            throw new Error(
              `Unmatched chain id for eth (expected: ${ethChainId}, actual: ${message.domain?.chainId})`
            );
          }
        }
        // XXX: There is no way to check chain id if type is message because eth personal sign standard doesn't define chain id field.
        // case EthSignType.MESSAGE:
      }
    }
  }

  if (!signOptions) {
    throw new KeplrError('keyring', 235, 'Sign options are null');
  }
}

export function createKeplrObject() {
  const chainsService = createChainsService();
  const masterSeed = generateMasterSeedFromMnemonic(
    'supply label curve utility satisfy wet alley about soda goddess useless frequent',
    ''
  );
  const chainId = 'cosmoshub-4';
  const coinType = chainsService.getChainCoinType(chainId);
  console.log({ coinType });
  const bip44HDPath = { account: 0, change: 0, addressIndex: 0 };
  const path = `m/44'/${coinType}'/${bip44HDPath.account}'/${bip44HDPath.change}/${bip44HDPath.addressIndex}`;
  const privKey = generatePrivateKeyFromMasterSeed(masterSeed, path);
  const privKeySec = new PrivKeySecp256k1(privKey);

  const keplrInstance = {
    getKey(chainId: string): Key & { bech32Address: string } {
      if (!chainId) {
        throw new KeplrError('keyring', 270, 'chain id not set');
      }
      const ethereumKeyFeatures =
        chainsService.getChainEthereumKeyFeatures(chainId);
      console.log({ ethereumKeyFeatures });
      const pubKey = privKeySec.getPubKey();
      let key;
      if (ethereumKeyFeatures.address) {
        // For Ethereum Key-Gen Only:
        const wallet = new Wallet(privKeySec.toBytes());
        key = {
          algo: 'ethsecp256k1',
          pubKey: pubKey.toBytes(),
          address: Buffer.from(wallet.address.replace('0x', ''), 'hex'),
          isNanoLedger: false,
        };
      } else {
        key = {
          algo: 'secp256k1',
          pubKey: pubKey.toBytes(),
          address: pubKey.getAddress(),
          isNanoLedger: false,
        };
      }
      return {
        // name: service.getKeyStoreMeta('name'),
        algo: 'secp256k1',
        pubKey: key.pubKey,
        address: key.address,
        bech32Address: new Bech32Address(key.address).toBech32(
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          chainsService.getChainInfo(chainId)!.bech32Config.bech32PrefixAccAddr
        ),
        isNanoLedger: key.isNanoLedger,
      };
    },
    async signAmino(
      chainId: string,
      signer: string,
      signDoc: StdSignDoc,
      signOptions: KeplrSignOptions & {
        // Hack option field to detect the sign arbitrary for string
        isADR36WithString?: boolean;
        ethSignType?: EthSignType;
      } = {}
    ): Promise<AminoSignResponse> {
      validateSignAmino(chainId, signer, signDoc, signOptions);
      signDoc = trimAminoSignDoc(signDoc);
      signDoc = sortObjectByKey(signDoc);
      const ethereumKeyFeatures =
        chainsService.getChainEthereumKeyFeatures(chainId);
      const key = keplrInstance.getKey(chainId);
      if (signer !== key.bech32Address) {
        throw new KeplrError('keyring', 231, 'Signer mismatched');
      }

      const bech32Prefix =
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        chainsService.getChainInfo(chainId)!.bech32Config.bech32PrefixAccAddr;

      const isADR36SignDoc = checkAndValidateADR36AminoSignDoc(
        signDoc,
        bech32Prefix
      );
      if (isADR36SignDoc) {
        if (signDoc.msgs[0].value.signer !== signer) {
          throw new KeplrError('keyring', 233, 'Unmatched signer in sign doc');
        }
      }

      if (signOptions.isADR36WithString != null && !isADR36SignDoc) {
        throw new KeplrError(
          'keyring',
          236,
          'Sign doc is not for ADR-36. But, "isADR36WithString" option is defined'
        );
      }

      if (signOptions.ethSignType && !isADR36SignDoc) {
        throw new Error(
          'Eth sign type can be requested with only ADR-36 amino sign doc'
        );
      }

      // this step is very important, check in live code if theres a change here
      const newSignDoc = signDoc;

      if (isADR36SignDoc) {
        // Validate the new sign doc, if it was for ADR-36.
        if (checkAndValidateADR36AminoSignDoc(signDoc, bech32Prefix)) {
          if (signDoc.msgs[0].value.signer !== signer) {
            throw new KeplrError(
              'keyring',
              232,
              'Unmatched signer in new sign doc'
            );
          }
        } else {
          throw new KeplrError(
            'keyring',
            237,
            'Signing request was for ADR-36. But, accidentally, new sign doc is not for ADR-36'
          );
        }
      }

      // Handle Ethereum signing
      if (signOptions.ethSignType) {
        if (newSignDoc.msgs.length !== 1) {
          // Validate number of messages
          throw new Error(
            'Invalid number of messages for Ethereum sign request'
          );
        }

        const signBytes = Buffer.from(newSignDoc.msgs[0].value.data, 'base64');

        const signatureBytes = await signEthereum(
          signBytes,
          signOptions.ethSignType,
          new Wallet(privKeySec.toBytes())
        );

        return {
          signed: newSignDoc, // Included to match return type
          signature: {
            pub_key: encodeSecp256k1Pubkey(key.pubKey), // Included to match return type
            signature: Buffer.from(signatureBytes).toString('base64'), // No byte limit
          },
        };
      }

      const signature = await sign(
        serializeSignDoc(newSignDoc),
        ethereumKeyFeatures.signing,
        privKeySec
      );

      return {
        signed: newSignDoc,
        signature: encodeSecp256k1Signature(key.pubKey, signature),
      };
    },
    async signDirect(
      chainId: string,
      signer: string,
      signDoc: {
        bodyBytes?: Uint8Array | null;
        authInfoBytes?: Uint8Array | null;
        chainId?: string | null;
        accountNumber?: Long | null | string;
      },
      // signOptions is used to show to user when ask for permissions
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      signOptions: KeplrSignOptions = {}
    ): Promise<DirectSignResponse> {
      signDoc.accountNumber = signDoc.accountNumber
        ? signDoc.accountNumber.toString()
        : null;
      const key = await keplrInstance.getKey(chainId);
      const ethereumKeyFeatures =
        chainsService.getChainEthereumKeyFeatures(chainId);
      const bech32Address = new Bech32Address(key.address).toBech32(
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        chainsService.getChainInfo(chainId)!.bech32Config.bech32PrefixAccAddr
      );
      if (signer !== bech32Address) {
        throw new KeplrError('keyring', 231, 'Signer mismatched');
      }

      const newSignDocBytes = SignDoc.encode(signDoc as SignDoc).finish();

      const newSignDoc = SignDoc.decode(newSignDocBytes);
      const { accountNumber: newSignDocAccountNumber, ...newSignDocRest } =
        newSignDoc;
      const cosmJSSignDoc = {
        ...newSignDocRest,
        accountNumber: Long.fromString(newSignDocAccountNumber),
      };

      const signature = await sign(
        makeSignBytes(cosmJSSignDoc),
        ethereumKeyFeatures.signing,
        privKeySec
      );

      const response = {
        signed: cosmJSSignDoc,
        signature: encodeSecp256k1Signature(key.pubKey, signature),
      };

      return {
        signed: {
          bodyBytes: response.signed.bodyBytes,
          authInfoBytes: response.signed.authInfoBytes,
          chainId: response.signed.chainId,
          accountNumber:
            response.signed.accountNumber.toString() as unknown as Long,
        },
        signature: response.signature,
      };
    },
  };
  return keplrInstance;
}

async function main() {
  const keplr = createKeplrObject();

  const key = keplr.getKey('cosmoshub-4');

  const signature = await keplr.signAmino(
    'cosmoshub-4',
    'cosmos1pqt4rsjxduzj797kh4w4c9ll2znlks33k4zxyf',
    {
      chain_id: 'cosmoshub-4',
      fee: {
        amount: [{ denom: 'point', amount: '1' }],
      },
      sequence: '1',
      memo: 'something',
    } as unknown as StdSignDoc
  );

  console.log({ key, pub: key.pubKey, add: key.address });
  console.log({ signature });

  // const signature = await keplr.signDirect(
  //   'cosmoshub-4',
  //   'cosmos1pqt4rsjxduzj797kh4w4c9ll2znlks33k4zxyf',
  //   bodyBytes?: Uint8Array | null;
  //   authInfoBytes?: Uint8Array | null;
  //   chainId?: string | null;
  //   accountNumber?: Long | null | string;
  // );

  console.log({ key, pub: key.pubKey, add: key.address });
  console.log({ signature });
}

main();
