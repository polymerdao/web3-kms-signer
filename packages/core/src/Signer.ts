import { addHexPrefix, fromSigned, toUnsigned, hashPersonalMessage, bigIntToBytes } from '@ethereumjs/util'
import { AccessListEIP2930TxData, BlobEIP4844TxData, LegacyTransaction } from '@ethereumjs/tx';
import { Common } from '@ethereumjs/common'
import { Wallets } from './Wallets';
import { UBuffer } from './Utils/UBuffer';
import {
    FeeMarketEIP1559TxData,
    isAccessListEIP2930TxData, isBlobEIP4844TxData,
    isFeeMarketEIP1559TxData,
    isLegacyTxData, TypedTxData
} from "@ethereumjs/tx/src/types";
import { FeeMarketEIP1559Transaction } from "@ethereumjs/tx/src/eip1559Transaction";
import type { PrefixedHexString } from "@ethereumjs/util/src/types";
import { AccessListEIP2930Transaction } from "@ethereumjs/tx/src/eip2930Transaction";
import { BlobEIP4844Transaction } from "@ethereumjs/tx/src/eip4844Transaction";

/**
 * The Signer class provides functionality to sign Ethereum transactions and messages using
 * private keys managed by a specified Wallets instance. It supports signing arbitrary messages,
 * hashed digests, and transaction data, preparing them for blockchain submission. The class
 * can be configured with a specific blockchain network through an optional chain ID, allowing
 * it to sign transactions according to network-specific parameters. It abstracts the complexities
 * of transaction serialization and signature generation, streamlining the process of creating
 * secure and valid blockchain transactions.
 * 
 */
export class Signer {
    wallets: Wallets;
    common?: Common;

    /**
     * Constructs a Signer instance with a specified Wallets instance and an optional chain ID.
     * The chain ID is used to configure the network for transactions.
     * @param wallets An instance of Wallets for key management and signing.
     * @param chainId Optional chain ID to specify the blockchain network.
     */
    constructor(wallets: Wallets, chainId?: number) {
        this.wallets = wallets;
        this.common = (chainId) ? Common.custom({ chainId: chainId, networkId: chainId }) : undefined;
    }

    /**
     * Signs an Ethereum transaction with the specified account's.
     * @param account An object containing the keyId and optional address of the signing account.
     * @param txData The transaction data to sign.
     * @returns A Promise that resolves to the serialized transaction as a '0x'-prefixed hex string.
     */
    public async signTransaction(account: { keyId: string, address?: Buffer }, txData: TypedTxData): Promise<PrefixedHexString> {
        if (isLegacyTxData(txData)) {
            const digest = LegacyTransaction.fromTxData(txData, { common: this.common }).getMessageToSign();
            const {r, s, v}  = await this.wallets.ecsign(account, Buffer.concat(digest), this.common?.chainId());
            const signed     = LegacyTransaction.fromTxData({...txData, r, s, v}, { common: this.common });
            return addHexPrefix(signed.serialize().toString('hex'));
        } else if (isFeeMarketEIP1559TxData(txData)) {
            const digest = FeeMarketEIP1559Transaction.fromTxData(txData, { common: this.common }).getMessageToSign();
            const {r, s, v}  = await this.wallets.ecsign(account, Buffer.from(digest), this.common?.chainId());
            const signed     = FeeMarketEIP1559Transaction.fromTxData({...txData as FeeMarketEIP1559TxData, r, s, v}, { common: this.common });
            return addHexPrefix(signed.serialize().toString('hex'));
        } else if (isAccessListEIP2930TxData(txData)) {
            const digest = AccessListEIP2930Transaction.fromTxData(txData, { common: this.common }).getMessageToSign();
            const {r, s, v}  = await this.wallets.ecsign(account, Buffer.from(digest), this.common?.chainId());
            const signed     = AccessListEIP2930Transaction.fromTxData({...txData as AccessListEIP2930TxData, r, s, v}, { common: this.common });
            return addHexPrefix(signed.serialize().toString('hex'));
        } else if (isBlobEIP4844TxData(txData)) {
            const digest = BlobEIP4844Transaction.fromTxData(txData, { common: this.common }).getMessageToSign();
            const {r, s, v}  = await this.wallets.ecsign(account, Buffer.from(digest), this.common?.chainId());
            const signed     = BlobEIP4844Transaction.fromTxData({...txData as BlobEIP4844TxData, r, s, v}, { common: this.common });
            return addHexPrefix(signed.serialize().toString('hex'));
        }
        throw new Error("Tx type is not supported")
    }

    /**
     * Signs an arbitrary message using the specified account's. The message is first
     * hashed and then signed.
     * @param account An object containing the keyId and optional address of the signing account.
     * @param message The message to sign.
     * @returns A Promise that resolves to the '0x'-prefixed hex string of the signature.
     */
    public async signMessage(account: { keyId: string, address?: Buffer }, message: string) {
        const digest = hashPersonalMessage(Buffer.from(message));
        return this.signDigest(account, digest);
    }

    /**
     * Signs a digest (hashed message) using the specified account's.
     * @param account An object containing the keyId and optional address of the signing account.
     * @param digest The digest to sign, either as a Buffer or a '0x'-prefixed hex string.
     * @returns A Promise that resolves to the '0x'-prefixed hex string of the signature.
     */
    public async signDigest(account: { keyId: string, address?: Buffer }, digest: string | Buffer) {
        const {r, s, v} = await this.wallets.ecsign(account, UBuffer.bufferOrHex(digest));

        const rStr = toUnsigned(fromSigned(r)).toString('hex');
        const sStr = toUnsigned(fromSigned(s)).toString('hex');
        const vStr = Buffer.from(bigIntToBytes(v)).toString('hex');

        return addHexPrefix(rStr.concat(sStr, vStr));
    }
}