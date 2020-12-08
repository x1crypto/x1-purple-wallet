// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

// Helper functions for serialization, see merkleblock.h
std::vector<unsigned char> BitsToBytesPH(const std::vector<bool>& bits);
std::vector<bool> BytesToBitsPH(const std::vector<unsigned char>& bytes);

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    mutable int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce); }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    uint256 GetPoWHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};

class CHeadersMessage : public CBlockHeader
{
public:
    /** the total number of transactions in the block */
    unsigned char nTransactions;

    /** dummy byte for blockcore compat */
    unsigned char nDummy;

    CHeadersMessage()
    {
        SetNull();
    }

    CHeadersMessage(const CBlockHeader& header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CHeadersMessage, obj)
    {
        // header
        READWRITEAS(CBlockHeader, obj);
        // zero values for nTransactions, nDummy for the headers message
        READWRITE(obj.nTransactions, obj.nDummy);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        nTransactions = 0;
        nDummy = 0;
    }
};

class CProvenBlockHeader : public CBlockHeader
{
public:
    /** the total number of transactions in the block */
    unsigned int nTransactions;

    /** txids and internal hashes */
    std::vector<uint256> vHash;

    /** node-is-parent-of-matched-txid bits */
    std::vector<bool> vBits;

    /** header signature w/ coinstake key */
    std::vector<unsigned char> vSignature;

    /** coinstake transaction */
    mutable CTransactionRef txProtocol;

    CProvenBlockHeader()
    {
        SetNull();
    }

    CProvenBlockHeader(const CBlockHeader& header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CProvenBlockHeader, obj)
    {
        // header
        READWRITEAS(CBlockHeader, obj);
        // merkle proof
        READWRITE(obj.nTransactions, obj.vHash);
        std::vector<unsigned char> bytes;
        SER_WRITE(obj, bytes = BitsToBytesPH(obj.vBits));
        READWRITE(bytes);
        SER_READ(obj, obj.vBits = BytesToBitsPH(bytes));
        // signature
        READWRITE(obj.vSignature);
        // transaction (serialization only, deserialization must be done separately)
        SER_WRITE(obj, obj.txProtocol->Serialize(s));
    }

   
	
    void SetNull()
    {
        CBlockHeader::SetNull();
        txProtocol = MakeTransactionRef(CTransaction());
    }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    /** signature of proof-of-stake blocks */
    std::vector<unsigned char> vPoSBlkSig;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader& header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vtx);
        READWRITE(obj.vPoSBlkSig);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vPoSBlkSig.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion = nVersion;
        block.hashPrevBlock = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator {
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
