// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

std::vector<unsigned char> BitsToBytesPH(const std::vector<bool>& bits)
{
    std::vector<unsigned char> ret((bits.size() + 7) / 8);
    for (unsigned int p = 0; p < bits.size(); p++) {
        ret[p / 8] |= bits[p] << (p % 8);
    }
    return ret;
}

std::vector<bool> BytesToBitsPH(const std::vector<unsigned char>& bytes)
{
    std::vector<bool> ret(bytes.size() * 8);
    for (unsigned int p = 0; p < ret.size(); p++) {
        ret[p] = (bytes[p / 8] & (1 << (p % 8))) != 0;
    }
    return ret;
}

uint256 CBlockHeader::GetHash() const
{
    if (this->nVersion == 1) {
        return SerializePoWHash(*this);
    }
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash() const
{
    return SerializePoWHash(*this);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
                   GetHash().ToString(),
                   nVersion,
                   hashPrevBlock.ToString(),
                   hashMerkleRoot.ToString(),
                   nTime, nBits, nNonce,
                   vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
