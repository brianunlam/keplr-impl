import { Hash } from './hash';

export async function sign(
  message: Uint8Array,
  useEthereumSigning: boolean,
  privKey: any
): Promise<Uint8Array> {
  const signature = useEthereumSigning
    ? privKey.signDigest32(Hash.keccak256(message))
    : privKey.sign(message);
  return signature;
}
