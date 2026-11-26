#include <openssl/ssl.h>

#include <algorithm>
#include <limits>

#include <openssl/bytestring.h>
#include <openssl/obj.h>
#include <openssl/pki/verify.h>
#include <openssl/pool.h>
#include <openssl/x509.h>

#include "../crypto/x509/internal.h"
#include "../pki/input.h"
#include "../pki/parse_values.h"
#include "../pki/parsed_certificate.h"
#include "../pki/trust_store_in_memory.h"
#include "internal.h"

BSSL_NAMESPACE_BEGIN

struct DAEMTCTrust {
  struct Log {
    std::shared_ptr<const MTCAnchor> anchor;
    std::vector<uint64_t> revoked;
  };
  std::unique_ptr<VerifyTrustStore> store;
  std::vector<Log> logs;
  std::vector<uint8_t> ids;
  uint64_t valid_from = 0;
  uint64_t expires = 0;

  bool IsCurrent(uint64_t now) const { return valid_from <= now && now < expires; }
};

bool ssl_dae_append_mtc_anchor_ids(SSL *ssl) {
  const auto &trust = *ssl->ctx->dae_mtc_trust;
  if (!trust.IsCurrent(ssl_ctx_get_current_time(ssl->ctx.get()).tv_sec)) {
    return true;
  }
  auto &requested = ssl->config->requested_trust_anchors;
  const size_t original_size = requested ? requested->size() : 0;
  Array<uint8_t> combined;
  if (original_size > 65533 - trust.ids.size() ||
      !combined.InitForOverwrite(original_size + trust.ids.size())) {
    return false;
  }
  if (original_size != 0) {
    OPENSSL_memcpy(combined.data(), requested->data(), original_size);
  }
  OPENSSL_memcpy(combined.data() + original_size, trust.ids.data(),
                 trust.ids.size());
  requested = std::move(combined);
  return true;
}

std::optional<int> ssl_dae_verify_mtc(const SSL_CTX *ctx,
                                      CRYPTO_BUFFER *certificate,
                                      X509_STORE_CTX *verify_context) {
  const ASN1_OBJECT *signature;
  const X509_ALGOR *algorithm = nullptr;
  X509_get0_signature(nullptr, &algorithm, X509_STORE_CTX_get0_cert(verify_context));
  X509_ALGOR_get0(&signature, nullptr, nullptr, algorithm);
  static constexpr uint8_t kProofOid[] = {0x2b, 0x06, 0x01, 0x04, 0x01,
                                          0x82, 0xda, 0x4b, 0x2f, 0x00};
  if (Span(OBJ_get0_data(signature), OBJ_length(signature)) != Span(kProofOid)) {
    return std::nullopt;
  }
  const auto fail = [&](int error) {
    X509_STORE_CTX_set_error(verify_context, error);
    return 0;
  };

  const auto &trust = *ctx->dae_mtc_trust;
  const uint64_t now = ssl_ctx_get_current_time(ctx).tv_sec;
  if (!trust.IsCurrent(now)) {
    return fail(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
  }
  auto leaf = ParsedCertificate::Create(UpRef(certificate), {}, nullptr);
  uint64_t serial;
  if (!leaf || !der::ParseUint64(leaf->tbs().serial_number, &serial)) {
    return fail(X509_V_ERR_CERT_SIGNATURE_FAILURE);
  }
  const auto log = std::find_if(trust.logs.begin(), trust.logs.end(),
      [&](const DAEMTCTrust::Log &entry) {
        return entry.anchor->NormalizedSubject() == leaf->normalized_issuer();
      });
  if (log == trust.logs.end()) {
    return fail(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
  }
  if (std::binary_search(log->revoked.begin(), log->revoked.end(), serial)) {
    return fail(X509_V_ERR_CERT_REVOKED);
  }

  CertificateVerifyOptions opts;
  opts.leaf_cert = BytesAsStringView(leaf->der_cert());
  opts.trust_store = trust.store.get();
  opts.time = static_cast<int64_t>(now);
  opts.min_rsa_modulus_length = 2048;
  opts.max_path_building_depth = 2;
  opts.max_iteration_count = 8;
  if (!CertificateVerify(opts)) {
    return fail(X509_V_ERR_CERT_SIGNATURE_FAILURE);
  }
  return 1;
}

BSSL_NAMESPACE_END

using namespace bssl;

// Network byte order. u64 valid_from, u64 expires, u16-prefixed ID list,
// then logs until EOF. Each log contains a u8-prefixed relative OID, a
// u16-prefixed subtree vector (u64 start, u64 end, SHA256 hash), and a
// u16-prefixed sorted vector of revoked u64 serials.
int DAE_SSL_CTX_set1_mtc_trust(SSL_CTX *ctx, const uint8_t *data, size_t len) {
  auto trust = std::make_shared<DAEMTCTrust>();
  CBS input(Span(data, len)), ids;
  if (!CBS_get_u64(&input, &trust->valid_from) ||
      !CBS_get_u64(&input, &trust->expires) ||
      trust->valid_from >= trust->expires ||
      trust->expires > uint64_t{std::numeric_limits<int64_t>::max()} ||
      !CBS_get_u16_length_prefixed(&input, &ids) || CBS_len(&ids) == 0 ||
      CBS_len(&ids) > 4096 || !ssl_is_valid_trust_anchor_list(ids)) {
    return 0;
  }
  trust->ids.assign(CBS_data(&ids), CBS_data(&ids) + CBS_len(&ids));
  trust->store = VerifyTrustStore::FromDER("", nullptr);
  if (!trust->store) {
    return 0;
  }
  while (CBS_len(&input) != 0) {
    CBS id, subtrees, revoked;
    if (trust->logs.size() == 32 ||
        !CBS_get_u8_length_prefixed(&input, &id) || CBS_len(&id) == 0 ||
        !CBS_get_u16_length_prefixed(&input, &subtrees) || CBS_len(&subtrees) == 0 ||
        !CBS_get_u16_length_prefixed(&input, &revoked)) {
      return 0;
    }
    std::vector<TrustedSubtree> checked_subtrees;
    while (CBS_len(&subtrees) != 0) {
      TrustedSubtree subtree;
      CBS hash;
      if (!CBS_get_u64(&subtrees, &subtree.range.start) ||
          !CBS_get_u64(&subtrees, &subtree.range.end) ||
          !CBS_get_bytes(&subtrees, &hash, subtree.hash.size()) ||
          (!checked_subtrees.empty() &&
           !(checked_subtrees.back().range < subtree.range))) {
        return 0;
      }
      OPENSSL_memcpy(subtree.hash.data(), CBS_data(&hash), subtree.hash.size());
      checked_subtrees.push_back(subtree);
    }
    DAEMTCTrust::Log log;
    log.anchor = std::make_shared<MTCAnchor>(id, Span(checked_subtrees));
    if (!trust->store->trust_store->AddMTCTrustAnchor(log.anchor)) {
      return 0;
    }
    while (CBS_len(&revoked) != 0) {
      uint64_t serial;
      if (!CBS_get_u64(&revoked, &serial) ||
          (!log.revoked.empty() && log.revoked.back() >= serial)) {
        return 0;
      }
      log.revoked.push_back(serial);
    }
    trust->logs.push_back(std::move(log));
  }
  if (trust->logs.empty()) {
    return 0;
  }
  ctx->dae_mtc_trust = std::move(trust);
  return 1;
}

int DAE_SSL_CTX_has_mtc_trust(const SSL_CTX *ctx) {
  return ctx->dae_mtc_trust != nullptr;
}
