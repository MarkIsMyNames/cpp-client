#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

struct MessageEnvelope {
    std::string schemaVersion{"securemsg-envelope-v1"};
    std::string messageType{"direct"};
    std::string conversationId;
    std::string messageId;
    std::string senderId;
    std::string recipientId;
    std::string ciphertext;
    std::string ratchetHeaderEnc;
    int64_t     sentAt{0};
};

struct SegmentDigest {
    std::string              segmentHash;
    std::vector<std::string> envelopeHashes;
    std::string              conversationId;
    std::string              segmentId;
    std::string              senderPublicKey;
    int                      messageCount{0};

    std::string  transactionHash;
    std::string  contractAddress;
    std::string  recorder;
    uint64_t     recordedTimestamp{0};
    int          chainId{11155111};
    std::string  chainName{"sepolia"};
};

class BlockchainManager {
public:
    static std::vector<uint8_t> keccak256(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> keccak256(const std::string& utf8);

    static std::string canonicalise(const MessageEnvelope& env);
    static std::vector<uint8_t> leafHash(const MessageEnvelope& env);
    static std::vector<uint8_t> segmentHash(const std::vector<std::vector<uint8_t>>& leafHashes);
    static std::vector<uint8_t> bundleHash(const std::vector<MessageEnvelope>& envs,
                                           const std::string& senderPublicKeyB64);

    static SegmentDigest buildSegmentDigest(const std::vector<MessageEnvelope>& envs,
                                            const std::string& conversationId,
                                            int segmentIndex,
                                            const std::string& senderPublicKeyB64 = {});

    // Writes Waleed's format: { sender_public_key, messages:[{index,ciphertext},...] }
    static std::string writeSegmentFile(const std::vector<MessageEnvelope>& envs,
                                        const SegmentDigest& digest);

    static std::vector<nlohmann::json> buildProofPackages(
        const std::vector<MessageEnvelope>& envs,
        const SegmentDigest& digest);

    static std::string writeProofPackagesFile(const std::vector<nlohmann::json>& packages,
                                              const std::string& segmentId);

    static std::string verifyLocalHashes(const nlohmann::json& package);
    static std::string verifyOnChain(const nlohmann::json& package, const std::string& rpcUrl);

    // Sign and submit the verifier bundle hash to the audit contract on Sepolia.
    // Returns the transaction hash on success, or a "FAIL: ..." string on error.
    static std::string recordOnChain(const std::string& bundleHashHex,
                                     const std::string& contractAddress,
                                     const std::string& privateKeyHex,
                                     const std::string& rpcUrl,
                                     int chainId = 11155111,
                                     const std::string& senderAddressHex = {});

    static std::string              toHex0x(const std::vector<uint8_t>& data);
    static std::vector<uint8_t>     fromHex0x(const std::string& hex);
};
