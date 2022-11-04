import { EthSignType } from '@keplr-wallet/types';
import * as BytesUtils from '@ethersproject/bytes';
import { _TypedDataEncoder } from '@ethersproject/hash';
import { TypedDataField } from '@ethersproject/abstract-signer';
import { EIP712MessageValidator } from './eip712';
import { Hash } from './hash';

export async function signEthereum(
  message: Uint8Array,
  type: EthSignType,
  ethWallet: any
): Promise<Uint8Array> {
  // // Allow signing with Ethereum for chains with coinType !== 60
  // const privKey = this.loadPrivKey(coinType);

  // const ethWallet = new Wallet(privKey.toBytes());

  switch (type) {
    case EthSignType.MESSAGE: {
      // Sign bytes with prefixed Ethereum magic
      const signature = await ethWallet.signMessage(message);
      return BytesUtils.arrayify(signature);
    }
    case EthSignType.TRANSACTION: {
      // Sign Ethereum transaction
      const signature = await ethWallet.signTransaction(
        JSON.parse(Buffer.from(message).toString())
      );
      return BytesUtils.arrayify(signature);
    }
    case EthSignType.EIP712: {
      const data = await EIP712MessageValidator.validateAsync(
        JSON.parse(Buffer.from(message).toString())
      );
      // Since ethermint eip712 tx uses non-standard format, it cannot pass validation of ethersjs.
      // Therefore, it should be handled at a slightly lower level.
      // eslint-disable-next-line no-underscore-dangle
      const signature = await ethWallet._signingKey().signDigest(
        Hash.keccak256(
          Buffer.concat([
            // eth separator
            Buffer.from('19', 'hex'),
            // Version: 1
            Buffer.from('01', 'hex'),
            Buffer.from(
              _TypedDataEncoder
                .hashStruct(
                  'EIP712Domain',
                  {
                    EIP712Domain: data.types
                      .EIP712Domain as unknown as TypedDataField[],
                  },
                  data.domain
                )
                .replace('0x', ''),
              'hex'
            ),
            Buffer.from(
              _TypedDataEncoder
                .from(
                  // Seems that there is no way to set primary type and the first type becomes primary type.
                  (() => {
                    const types = { ...data.types };
                    delete types.EIP712Domain;
                    const primary = types[data.primaryType];
                    if (!primary) {
                      throw new Error(
                        `No matched primary type: ${data.primaryType}`
                      );
                    }
                    delete types[data.primaryType];
                    return {
                      [data.primaryType]: primary,
                      ...types,
                    };
                  })() as unknown as Record<string, TypedDataField[]>
                )
                .hash(data.message)
                .replace('0x', ''),
              'hex'
            ),
          ])
        )
      );
      return Buffer.concat([
        Buffer.from(signature.r.replace('0x', ''), 'hex'),
        Buffer.from(signature.s.replace('0x', ''), 'hex'),
        // The metamask doesn't seem to consider the chain id in this case... (maybe bug on metamask?)
        signature.recoveryParam
          ? Buffer.from('1c', 'hex')
          : Buffer.from('1b', 'hex'),
      ]);
    }
    default:
      throw new Error(`Unknown sign type: ${type}`);
  }
}
