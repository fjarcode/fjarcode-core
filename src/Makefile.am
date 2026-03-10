


# Pattern rule to print variables, e.g. make print-top_srcdir
print-%: FORCE
	@echo '$*'='$($*)'

DIST_SUBDIRS = secp256k1

AM_LDFLAGS = $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS) $(GPROF_LDFLAGS) $(SANITIZER_LDFLAGS) $(CORE_LDFLAGS)
AM_CXXFLAGS = $(CORE_CXXFLAGS) $(DEBUG_CXXFLAGS) $(HARDENED_CXXFLAGS) $(WARN_CXXFLAGS) $(NOWARN_CXXFLAGS) $(ERROR_CXXFLAGS) $(GPROF_CXXFLAGS) $(SANITIZER_CXXFLAGS)
AM_CPPFLAGS = $(DEBUG_CPPFLAGS) $(HARDENED_CPPFLAGS) $(CORE_CPPFLAGS)
AM_LIBTOOLFLAGS = --preserve-dup-deps
PTHREAD_FLAGS = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
EXTRA_LIBRARIES =

lib_LTLIBRARIES =
noinst_LTLIBRARIES =

bin_PROGRAMS =
noinst_PROGRAMS =
check_PROGRAMS =
TESTS =
BENCHMARKS =

FJARCODE_INCLUDES=-I$(builddir) -I$(srcdir)/$(MINISKETCH_INCLUDE_DIR_INT) -I$(srcdir)/secp256k1/include -I$(srcdir)/$(UNIVALUE_INCLUDE_DIR_INT)

LIBFJARCODE_NODE=libfjarcode_node.a
LIBFJARCODE_COMMON=libfjarcode_common.a
LIBFJARCODE_CONSENSUS=libfjarcode_consensus.a
LIBFJARCODE_CLI=libfjarcode_cli.a
LIBFJARCODE_UTIL=libfjarcode_util.a
LIBFJARCODE_CRYPTO_BASE=crypto/libfjarcode_crypto_base.la
LIBFJARCODEQT=qt/libfjarcodeqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

if ENABLE_ZMQ
LIBFJARCODE_ZMQ=libfjarcode_zmq.a
endif
if BUILD_FJARCODE_LIBS
LIBFJARCODECONSENSUS=libfjarcodeconsensus.la
endif
if BUILD_FJARCODE_KERNEL_LIB
LIBFJARCODEKERNEL=libfjarcodekernel.la
endif
if ENABLE_WALLET
LIBFJARCODE_WALLET=libfjarcode_wallet.a
LIBFJARCODE_WALLET_TOOL=libfjarcode_wallet_tool.a
endif

LIBFJARCODE_CRYPTO = $(LIBFJARCODE_CRYPTO_BASE)
if ENABLE_SSE41
LIBFJARCODE_CRYPTO_SSE41 = crypto/libfjarcode_crypto_sse41.la
LIBFJARCODE_CRYPTO += $(LIBFJARCODE_CRYPTO_SSE41)
endif
if ENABLE_AVX2
LIBFJARCODE_CRYPTO_AVX2 = crypto/libfjarcode_crypto_avx2.la
LIBFJARCODE_CRYPTO += $(LIBFJARCODE_CRYPTO_AVX2)
endif
if ENABLE_X86_SHANI
LIBFJARCODE_CRYPTO_X86_SHANI = crypto/libfjarcode_crypto_x86_shani.la
LIBFJARCODE_CRYPTO += $(LIBFJARCODE_CRYPTO_X86_SHANI)
endif
if ENABLE_ARM_SHANI
LIBFJARCODE_CRYPTO_ARM_SHANI = crypto/libfjarcode_crypto_arm_shani.la
LIBFJARCODE_CRYPTO += $(LIBFJARCODE_CRYPTO_ARM_SHANI)
endif
noinst_LTLIBRARIES += $(LIBFJARCODE_CRYPTO)

$(LIBSECP256K1): $(wildcard secp256k1/src/*.h) $(wildcard secp256k1/src/*.c) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBFJARCODE_UTIL) \
  $(LIBFJARCODE_COMMON) \
  $(LIBFJARCODE_CONSENSUS) \
  $(LIBFJARCODE_NODE) \
  $(LIBFJARCODE_CLI) \
  $(LIBFJARCODE_IPC) \
  $(LIBFJARCODE_WALLET) \
  $(LIBFJARCODE_WALLET_TOOL) \
  $(LIBFJARCODE_ZMQ)

if BUILD_FJARCODED
  bin_PROGRAMS += fjarcoded
endif

if BUILD_FJARCODE_NODE
  bin_PROGRAMS += fjarcode-node
endif

if BUILD_FJARCODE_CLI
  bin_PROGRAMS += fjarcode-cli
endif

if BUILD_FJARCODE_TX
  bin_PROGRAMS += fjarcode-tx
endif

if ENABLE_WALLET
if BUILD_FJARCODE_WALLET
  bin_PROGRAMS += fjarcode-wallet
endif
endif

if BUILD_FJARCODE_UTIL
  bin_PROGRAMS += fjarcode-util
endif

if BUILD_FJARCODE_CHAINSTATE
  bin_PROGRAMS += fjarcode-chainstate
endif

if BUILD_SEEDER
  bin_PROGRAMS += fjar-seeder
  EXTRA_LIBRARIES += $(LIBFJARCODE_SEEDER) $(LIBFJARCODE_SEEDER_INIT)
endif

.PHONY: FORCE check-symbols check-security
# fjarcode core #
FJARCODE_CORE_H = \
  addresstype.h \
  addrdb.h \
  algorithm/algorithm.h \
  algorithm/contains.h \
  algorithm/erase_if.h \
  algorithm/type_attributes.h \
  addrman.h \
  addrman_impl.h \
  attributes.h \
  banman.h \
  base58.h \
  bech32.h \
  bip324.h \
  blockencodings.h \
  blockfilter.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  common/args.h \
  common/bloom.h \
  common/init.h \
  common/run_command.h \
  common/url.h \
  compat/assumptions.h \
  compat/byteswap.h \
  compat/compat.h \
  compat/cpuid.h \
  compat/endian.h \
  common/settings.h \
  common/system.h \
  compressor.h \
  consensus/consensus.h \
  consensus/tx_check.h \
  consensus/tx_verify.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  dbwrapper.h \
  deploymentinfo.h \
  deploymentstatus.h \
  external_signer.h \
  fjarcode_fork.h \
  flatfile.h \
  headerssync.h \
  httprpc.h \
  httpserver.h \
  i2p.h \
  index/base.h \
  index/blockfilterindex.h \
  index/coinstatsindex.h \
  index/disktxpos.h \
  index/txindex.h \
  indirectmap.h \
  init.h \
  init/common.h \
  interfaces/chain.h \
  interfaces/echo.h \
  interfaces/handler.h \
  interfaces/init.h \
  interfaces/ipc.h \
  interfaces/node.h \
  interfaces/wallet.h \
  kernel/blockmanager_opts.h \
  kernel/chain.h \
  kernel/chainparams.h \
  kernel/chainstatemanager_opts.h \
  kernel/checks.h \
  kernel/coinstats.h \
  kernel/context.h \
  kernel/cs_main.h \
  kernel/disconnected_transactions.h \
  kernel/mempool_entry.h \
  kernel/mempool_limits.h \
  kernel/mempool_options.h \
  kernel/mempool_persist.h \
  kernel/mempool_removal_reason.h \
  kernel/messagestartchars.h \
  kernel/notifications_interface.h \
  kernel/validation_cache_sizes.h \
  key.h \
  key_io.h \
  cashaddr.h \
  logging.h \
  logging/timer.h \
  mapport.h \
  memusage.h \
  merkleblock.h \
  net.h \
  net_permissions.h \
  net_processing.h \
  net_types.h \
  netaddress.h \
  netbase.h \
  netgroup.h \
  netmessagemaker.h \
  node/abort.h \
  node/blockmanager_args.h \
  node/blockstorage.h \
  node/caches.h \
  node/chainstate.h \
  node/chainstatemanager_args.h \
  node/coin.h \
  node/coins_view_args.h \
  node/connection_types.h \
  node/context.h \
  node/database_args.h \
  node/eviction.h \
  node/interface_ui.h \
  node/kernel_notifications.h \
  node/mempool_args.h \
  node/mempool_persist_args.h \
  node/miner.h \
  node/mini_miner.h \
  node/minisketchwrapper.h \
  node/peerman_args.h \
  node/protocol_version.h \
  node/psbt.h \
  node/transaction.h \
  node/txreconciliation.h \
  node/utxo_snapshot.h \
  node/validation_cache_args.h \
  noui.h \
  outputtype.h \
  policy/v3_policy.h \
  policy/feerate.h \
  policy/fees.h \
  policy/fees_args.h \
  policy/packages.h \
  policy/policy.h \
  policy/rbf.h \
  policy/settings.h \
  pow.h \
  protocol.h \
  psbt.h \
  random.h \
  randomenv.h \
  rest.h \
  reverse_iterator.h \
  rpc/blockchain.h \
  rpc/client.h \
  rpc/mempool.h \
  rpc/mining.h \
  rpc/protocol.h \
  rpc/rawtransaction_util.h \
  rpc/register.h \
  rpc/request.h \
  rpc/server.h \
  rpc/server_util.h \
  rpc/util.h \
  scheduler.h \
  seeder/bitcoin.h \
  seeder/db.h \
  seeder/dns.h \
  seeder/util.h \
  script/descriptor.h \
  script/keyorigin.h \
  script/miniscript.h \
  script/scriptcache.h \
  script/sigcache.h \
  script/sign.h \
  script/signingprovider.h \
  script/solver.h \
  signet.h \
  streams.h \
  support/allocators/pool.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  txorphanage.h \
  txrequest.h \
  undo.h \
  util/any.h \
  util/asmap.h \
  util/batchpriority.h \
  util/bip32.h \
  util/bitdeque.h \
  util/bytevectorhash.h \
  util/chaintype.h \
  util/check.h \
  util/epochguard.h \
  util/error.h \
  util/defer.h \
  util/exception.h \
  util/fastrange.h \
  util/fees.h \
  util/fs.h \
  util/fs_helpers.h \
  util/golombrice.h \
  util/hash_type.h \
  util/hasher.h \
  util/insert.h \
  util/macros.h \
  util/message.h \
  util/moneystr.h \
  util/overflow.h \
  util/overloaded.h \
  util/rbf.h \
  util/readwritefile.h \
  util/result.h \
  util/serfloat.h \
  util/signalinterrupt.h \
  util/sock.h \
  util/spanparsing.h \
  util/string.h \
  util/syserror.h \
  util/thread.h \
  util/threadinterrupt.h \
  util/threadnames.h \
  util/time.h \
  util/tokenpipe.h \
  util/trace.h \
  util/transaction_identifier.h \
  util/translation.h \
  util/types.h \
  util/ui_change_type.h \
  util/vector.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  wallet/bdb.h \
  wallet/coincontrol.h \
  wallet/coinselection.h \
  wallet/context.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/dump.h \
  wallet/external_signer_scriptpubkeyman.h \
  wallet/feebumper.h \
  wallet/fees.h \
  wallet/load.h \
  wallet/receive.h \
  wallet/rpc/util.h \
  wallet/rpc/wallet.h \
  wallet/salvage.h \
  wallet/scriptpubkeyman.h \
  wallet/spend.h \
  wallet/sqlite.h \
  wallet/transaction.h \
  wallet/types.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/wallettool.h \
  wallet/walletutil.h \
  walletinitinterface.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h \
  zmq/zmqrpc.h \
  zmq/zmqutil.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	$(AM_V_GEN) $(top_srcdir)/share/genbuild.sh "$(abs_top_builddir)/src/obj/build.h" \
	  "$(abs_top_srcdir)"
libfjarcode_util_a-clientversion.$(OBJEXT): obj/build.h

# node #
libfjarcode_node_a_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES) $(LEVELDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(MINIUPNPC_CPPFLAGS) $(NATPMP_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libfjarcode_node_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libfjarcode_node_a_SOURCES = \
  addrdb.cpp \
  addrman.cpp \
  banman.cpp \
  bip324.cpp \
  blockencodings.cpp \
  blockfilter.cpp \
  chain.cpp \
  consensus/tx_verify.cpp \
  dbwrapper.cpp \
  deploymentstatus.cpp \
  dsp/dspid.h \
  dsp/dsproof.cpp \
  dsp/dsproof.h \
  dsp/dsproof_create.cpp \
  dsp/dsproof_validate.cpp \
  dsp/storage.cpp \
  dsp/storage.h \
  dsp/storage_cleanup.cpp \
  flatfile.cpp \
  gbtlight.cpp \
  gbtlight.h \
  headerssync.cpp \
  httprpc.cpp \
  httpserver.cpp \
  i2p.cpp \
  index/base.cpp \
  index/blockfilterindex.cpp \
  index/coinstatsindex.cpp \
  index/txindex.cpp \
  init.cpp \
  kernel/chain.cpp \
  kernel/checks.cpp \
  kernel/coinstats.cpp \
  kernel/context.cpp \
  kernel/cs_main.cpp \
  kernel/disconnected_transactions.cpp \
  kernel/mempool_persist.cpp \
  kernel/mempool_removal_reason.cpp \
  mapport.cpp \
  net.cpp \
  net_processing.cpp \
  netgroup.cpp \
  node/abort.cpp \
  node/blockmanager_args.cpp \
  node/blockstorage.cpp \
  node/caches.cpp \
  node/chainstate.cpp \
  node/chainstatemanager_args.cpp \
  node/coin.cpp \
  node/coins_view_args.cpp \
  node/connection_types.cpp \
  node/context.cpp \
  node/database_args.cpp \
  node/eviction.cpp \
  node/interface_ui.cpp \
  node/interfaces.cpp \
  node/kernel_notifications.cpp \
  node/mempool_args.cpp \
  node/mempool_persist_args.cpp \
  node/miner.cpp \
  node/mini_miner.cpp \
  node/minisketchwrapper.cpp \
  node/peerman_args.cpp \
  node/psbt.cpp \
  node/transaction.cpp \
  node/txreconciliation.cpp \
  node/utxo_snapshot.cpp \
  node/validation_cache_args.cpp \
  noui.cpp \
  policy/v3_policy.cpp \
  policy/fees.cpp \
  policy/fees_args.cpp \
  policy/packages.cpp \
  policy/rbf.cpp \
  policy/settings.cpp \
  pow.cpp \
  rest.cpp \
  rpc/abc.cpp \
  rpc/blockchain.cpp \
  rpc/dsproof.cpp \
  rpc/fees.cpp \
  rpc/mempool.cpp \
  rpc/mining.cpp \
  rpc/net.cpp \
  rpc/node.cpp \
  rpc/output_script.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  rpc/server_util.cpp \
  rpc/signmessage.cpp \
  rpc/txoutproof.cpp \
  script/scriptcache.cpp \
  script/sigcache.cpp \
  signet.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  txorphanage.cpp \
  txrequest.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(FJARCODE_CORE_H)

if ENABLE_WALLET
libfjarcode_node_a_SOURCES += wallet/init.cpp
libfjarcode_node_a_CPPFLAGS += $(BDB_CPPFLAGS)
endif
if !ENABLE_WALLET
libfjarcode_node_a_SOURCES += dummywallet.cpp
endif
#

# zmq #
if ENABLE_ZMQ
libfjarcode_zmq_a_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES) $(ZMQ_CFLAGS)
libfjarcode_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libfjarcode_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp \
  zmq/zmqrpc.cpp \
  zmq/zmqutil.cpp
endif
#

# wallet #
libfjarcode_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES) $(BOOST_CPPFLAGS) $(BDB_CPPFLAGS) $(SQLITE_CFLAGS)
libfjarcode_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libfjarcode_wallet_a_SOURCES = \
  wallet/coincontrol.cpp \
  wallet/context.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/dump.cpp \
  wallet/external_signer_scriptpubkeyman.cpp \
  wallet/feebumper.cpp \
  wallet/fees.cpp \
  wallet/interfaces.cpp \
  wallet/load.cpp \
  wallet/receive.cpp \
  wallet/rpc/addresses.cpp \
  wallet/rpc/backup.cpp \
  wallet/rpc/coins.cpp \
  wallet/rpc/encrypt.cpp \
  wallet/rpc/spend.cpp \
  wallet/rpc/signmessage.cpp \
  wallet/rpc/transactions.cpp \
  wallet/rpc/util.cpp \
  wallet/rpc/wallet.cpp \
  wallet/scriptpubkeyman.cpp \
  wallet/spend.cpp \
  wallet/transaction.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/walletutil.cpp \
  wallet/coinselection.cpp \
  $(FJARCODE_CORE_H)

if USE_SQLITE
libfjarcode_wallet_a_SOURCES += wallet/sqlite.cpp
endif
if USE_BDB
libfjarcode_wallet_a_SOURCES += wallet/bdb.cpp wallet/salvage.cpp
endif
#

# wallet tool #
libfjarcode_wallet_tool_a_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES) $(BOOST_CPPFLAGS)
libfjarcode_wallet_tool_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libfjarcode_wallet_tool_a_SOURCES = \
  wallet/wallettool.cpp \
  $(FJARCODE_CORE_H)
#

# crypto #

# crypto_base contains the unspecialized (unoptimized) versions of our
# crypto functions. Functions that require custom compiler flags and/or
# runtime opt-in are omitted.
crypto_libfjarcode_crypto_base_la_CPPFLAGS = $(AM_CPPFLAGS)

# Specify -static in both CXXFLAGS and LDFLAGS so libtool will only build a
# static version of this library. We don't need a dynamic version, and a dynamic
# version can't be used on windows anyway because the library doesn't currently
# export DLL symbols.
crypto_libfjarcode_crypto_base_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -static
crypto_libfjarcode_crypto_base_la_LDFLAGS = $(AM_LDFLAGS) -static

crypto_libfjarcode_crypto_base_la_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/chacha20poly1305.h \
  crypto/chacha20poly1305.cpp \
  crypto/common.h \
  crypto/hkdf_sha256_32.cpp \
  crypto/hkdf_sha256_32.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/poly1305.h \
  crypto/poly1305.cpp \
  crypto/muhash.h \
  crypto/muhash.cpp \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha256_sse4.cpp \
  crypto/sha3.cpp \
  crypto/sha3.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/siphash.cpp \
  crypto/siphash.h

# See explanation for -static in crypto_libfjarcode_crypto_base_la's LDFLAGS and
# CXXFLAGS above
crypto_libfjarcode_crypto_sse41_la_LDFLAGS = $(AM_LDFLAGS) -static
crypto_libfjarcode_crypto_sse41_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -static
crypto_libfjarcode_crypto_sse41_la_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libfjarcode_crypto_sse41_la_CXXFLAGS += $(SSE41_CXXFLAGS)
crypto_libfjarcode_crypto_sse41_la_CPPFLAGS += -DENABLE_SSE41
crypto_libfjarcode_crypto_sse41_la_SOURCES = crypto/sha256_sse41.cpp

# See explanation for -static in crypto_libfjarcode_crypto_base_la's LDFLAGS and
# CXXFLAGS above
crypto_libfjarcode_crypto_avx2_la_LDFLAGS = $(AM_LDFLAGS) -static
crypto_libfjarcode_crypto_avx2_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -static
crypto_libfjarcode_crypto_avx2_la_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libfjarcode_crypto_avx2_la_CXXFLAGS += $(AVX2_CXXFLAGS)
crypto_libfjarcode_crypto_avx2_la_CPPFLAGS += -DENABLE_AVX2
crypto_libfjarcode_crypto_avx2_la_SOURCES = crypto/sha256_avx2.cpp

# See explanation for -static in crypto_libfjarcode_crypto_base_la's LDFLAGS and
# CXXFLAGS above
crypto_libfjarcode_crypto_x86_shani_la_LDFLAGS = $(AM_LDFLAGS) -static
crypto_libfjarcode_crypto_x86_shani_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -static
crypto_libfjarcode_crypto_x86_shani_la_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libfjarcode_crypto_x86_shani_la_CXXFLAGS += $(X86_SHANI_CXXFLAGS)
crypto_libfjarcode_crypto_x86_shani_la_CPPFLAGS += -DENABLE_X86_SHANI
crypto_libfjarcode_crypto_x86_shani_la_SOURCES = crypto/sha256_x86_shani.cpp

# See explanation for -static in crypto_libfjarcode_crypto_base_la's LDFLAGS and
# CXXFLAGS above
crypto_libfjarcode_crypto_arm_shani_la_LDFLAGS = $(AM_LDFLAGS) -static
crypto_libfjarcode_crypto_arm_shani_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -static
crypto_libfjarcode_crypto_arm_shani_la_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libfjarcode_crypto_arm_shani_la_CXXFLAGS += $(ARM_SHANI_CXXFLAGS)
crypto_libfjarcode_crypto_arm_shani_la_CPPFLAGS += -DENABLE_ARM_SHANI
crypto_libfjarcode_crypto_arm_shani_la_SOURCES = crypto/sha256_arm_shani.cpp
#

# consensus #
libfjarcode_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES)
libfjarcode_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libfjarcode_consensus_a_SOURCES = \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/abla.cpp \
  consensus/abla.h \
  consensus/activation.h \
  consensus/amount.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/tokens.cpp \
  consensus/tokens.h \
  consensus/tx_check.cpp \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/blockhash.h \
  primitives/token.cpp \
  primitives/token.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  primitives/txid.h \
  pubkey.cpp \
  pubkey.h \
  script/bitfield.cpp \
  script/bitfield.h \
  script/fjarcodeconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  script/script_execution_context.h \
  script/script_num_encoding.cpp \
  script/script_num_encoding.h \
  serialize.h \
  span.h \
  streams.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  util/heapoptional.h \
  util/strencodings.cpp \
  util/strencodings.h
#

# common #
libfjarcode_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES) $(BOOST_CPPFLAGS)
libfjarcode_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libfjarcode_common_a_SOURCES = \
  addresstype.cpp \
  base58.cpp \
  bech32.cpp \
  chainparams.cpp \
  coins.cpp \
  common/args.cpp \
  common/bloom.cpp \
  common/config.cpp \
  common/init.cpp \
  common/interfaces.cpp \
  common/run_command.cpp \
  common/settings.cpp \
  common/system.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  deploymentinfo.cpp \
  external_signer.cpp \
  init/common.cpp \
  kernel/chainparams.cpp \
  key.cpp \
  key_io.cpp \
  cashaddr.cpp \
  merkleblock.cpp \
  net_types.cpp \
  netaddress.cpp \
  netbase.cpp \
  net_permissions.cpp \
  outputtype.cpp \
  policy/v3_policy.cpp \
  policy/feerate.cpp \
  policy/policy.cpp \
  protocol.cpp \
  psbt.cpp \
  rpc/external_signer.cpp \
  rpc/rawtransaction_util.cpp \
  rpc/request.cpp \
  rpc/util.cpp \
  scheduler.cpp \
  script/descriptor.cpp \
  script/miniscript.cpp \
  script/sign.cpp \
  script/signingprovider.cpp \
  script/solver.cpp \
  warnings.cpp \
  $(FJARCODE_CORE_H)

if USE_LIBEVENT
libfjarcode_common_a_CPPFLAGS += $(EVENT_CFLAGS)
libfjarcode_common_a_SOURCES += common/url.cpp
endif
#

# util #
libfjarcode_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES)
libfjarcode_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libfjarcode_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  logging.cpp \
  random.cpp \
  randomenv.cpp \
  streams.cpp \
  support/cleanse.cpp \
  sync.cpp \
  util/asmap.cpp \
  util/batchpriority.cpp \
  util/bip32.cpp \
  util/bytevectorhash.cpp \
  util/chaintype.cpp \
  util/check.cpp \
  util/error.cpp \
  util/exception.cpp \
  util/fees.cpp \
  util/fs.cpp \
  util/fs_helpers.cpp \
  util/hasher.cpp \
  util/sock.cpp \
  util/syserror.cpp \
  util/message.cpp \
  util/moneystr.cpp \
  util/rbf.cpp \
  util/readwritefile.cpp \
  util/signalinterrupt.cpp \
  util/thread.cpp \
  util/threadinterrupt.cpp \
  util/threadnames.cpp \
  util/serfloat.cpp \
  util/spanparsing.cpp \
  util/strencodings.cpp \
  util/string.cpp \
  util/time.cpp \
  util/tokenpipe.cpp \
  $(FJARCODE_CORE_H)
#

# cli #
libfjarcode_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES)
libfjarcode_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libfjarcode_cli_a_SOURCES = \
  compat/stdin.h \
  compat/stdin.cpp \
  rpc/client.cpp \
  $(FJARCODE_CORE_H)

nodist_libfjarcode_util_a_SOURCES = $(srcdir)/obj/build.h
#

# fjarcoded & fjarcode-node binaries #
fjarcode_daemon_sources = fjarcoded.cpp
fjarcode_bin_cppflags = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES)
fjarcode_bin_cxxflags = $(AM_CXXFLAGS) $(PIE_FLAGS)
fjarcode_bin_ldflags = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
fjarcode_daemon_sources += fjarcoded-res.rc
endif

fjarcode_bin_ldadd = \
  $(LIBFJARCODE_WALLET) \
  $(LIBFJARCODE_COMMON) \
  $(LIBFJARCODE_UTIL) \
  $(LIBUNIVALUE) \
  $(LIBFJARCODE_ZMQ) \
  $(LIBFJARCODE_CONSENSUS) \
  $(LIBFJARCODE_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

fjarcode_bin_ldadd += $(BDB_LIBS) $(MINIUPNPC_LIBS) $(NATPMP_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS) $(SQLITE_LIBS)

fjarcoded_SOURCES = $(fjarcode_daemon_sources) init/fjarcoded.cpp
fjarcoded_CPPFLAGS = $(fjarcode_bin_cppflags)
fjarcoded_CXXFLAGS = $(fjarcode_bin_cxxflags)
fjarcoded_LDFLAGS = $(fjarcode_bin_ldflags)
fjarcoded_LDADD = $(LIBFJARCODE_NODE) $(fjarcode_bin_ldadd)

fjarcode_node_SOURCES = $(fjarcode_daemon_sources) init/fjarcode-node.cpp
fjarcode_node_CPPFLAGS = $(fjarcode_bin_cppflags)
fjarcode_node_CXXFLAGS = $(fjarcode_bin_cxxflags)
fjarcode_node_LDFLAGS = $(fjarcode_bin_ldflags)
fjarcode_node_LDADD = $(LIBFJARCODE_NODE) $(fjarcode_bin_ldadd) $(LIBFJARCODE_IPC) $(LIBMULTIPROCESS_LIBS)

# fjarcode-cli binary #
fjarcode_cli_SOURCES = fjarcode-cli.cpp
fjarcode_cli_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES) $(EVENT_CFLAGS)
fjarcode_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
fjarcode_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
fjarcode_cli_SOURCES += fjarcode-cli-res.rc
endif

fjarcode_cli_LDADD = \
  $(LIBFJARCODE_CLI) \
  $(LIBUNIVALUE) \
  $(LIBFJARCODE_COMMON) \
  $(LIBFJARCODE_UTIL) \
  $(LIBFJARCODE_CRYPTO)

fjarcode_cli_LDADD += $(EVENT_LIBS)
#

# fjarcode-tx binary #
fjarcode_tx_SOURCES = fjarcode-tx.cpp
fjarcode_tx_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES)
fjarcode_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
fjarcode_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
fjarcode_tx_SOURCES += fjarcode-tx-res.rc
endif

fjarcode_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBFJARCODE_COMMON) \
  $(LIBFJARCODE_UTIL) \
  $(LIBFJARCODE_CONSENSUS) \
  $(LIBFJARCODE_CRYPTO) \
  $(LIBSECP256K1)
#

# fjarcode-wallet binary #
fjarcode_wallet_SOURCES = fjarcode-wallet.cpp
fjarcode_wallet_SOURCES += init/fjarcode-wallet.cpp
fjarcode_wallet_CPPFLAGS = $(fjarcode_bin_cppflags)
fjarcode_wallet_CXXFLAGS = $(fjarcode_bin_cxxflags)
fjarcode_wallet_LDFLAGS = $(fjarcode_bin_ldflags)
fjarcode_wallet_LDADD = \
  $(LIBFJARCODE_WALLET_TOOL) \
  $(LIBFJARCODE_WALLET) \
  $(LIBFJARCODE_COMMON) \
  $(LIBFJARCODE_UTIL) \
  $(LIBUNIVALUE) \
  $(LIBFJARCODE_CONSENSUS) \
  $(LIBFJARCODE_CRYPTO) \
  $(LIBSECP256K1) \
  $(BDB_LIBS) \
  $(SQLITE_LIBS)

if TARGET_WINDOWS
fjarcode_wallet_SOURCES += fjarcode-wallet-res.rc
endif
#

# fjarcode-util binary #
fjarcode_util_SOURCES = fjarcode-util.cpp
fjarcode_util_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES)
fjarcode_util_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
fjarcode_util_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
fjarcode_util_SOURCES += fjarcode-util-res.rc
endif

fjarcode_util_LDADD = \
  $(LIBFJARCODE_COMMON) \
  $(LIBFJARCODE_UTIL) \
  $(LIBUNIVALUE) \
  $(LIBFJARCODE_CONSENSUS) \
  $(LIBFJARCODE_CRYPTO) \
  $(LIBSECP256K1)
#

# fjarcode-chainstate binary #
fjarcode_chainstate_SOURCES = fjarcode-chainstate.cpp
fjarcode_chainstate_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES) $(BOOST_CPPFLAGS)
fjarcode_chainstate_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

fjarcode_chainstate_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(PTHREAD_FLAGS) $(LIBTOOL_APP_LDFLAGS) -static
fjarcode_chainstate_LDADD = $(LIBFJARCODEKERNEL)

# libtool is unable to calculate this indirect dependency, presumably because it's a subproject.
# libsecp256k1 only needs to be linked in when libfjarcodekernel is static.
fjarcode_chainstate_LDADD += $(LIBSECP256K1)
#

# fjar-seeder DNS seeder #
LIBFJARCODE_SEEDER=libfjarcode_seeder.a
LIBFJARCODE_SEEDER_INIT=libfjarcode_seeder_init.a

libfjarcode_seeder_a_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES)
libfjarcode_seeder_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libfjarcode_seeder_a_SOURCES = \
  seeder/bitcoin.cpp \
  seeder/db.cpp \
  seeder/dns.cpp \
  seeder/main.cpp \
  seeder/util.cpp

# Small library that defines G_TRANSLATION_FUN, linked LAST
libfjarcode_seeder_init_a_CPPFLAGS = $(AM_CPPFLAGS)
libfjarcode_seeder_init_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libfjarcode_seeder_init_a_SOURCES = seeder/translation.cpp

fjar_seeder_SOURCES = seeder/seeder_main.cpp
fjar_seeder_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES)
fjar_seeder_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
fjar_seeder_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)
fjar_seeder_LDADD = \
  $(LIBFJARCODE_SEEDER) \
  $(LIBFJARCODE_COMMON) \
  $(LIBFJARCODE_UTIL) \
  $(LIBUNIVALUE) \
  $(LIBFJARCODE_CONSENSUS) \
  $(LIBFJARCODE_CRYPTO) \
  $(LIBSECP256K1) \
  $(LIBFJARCODE_SEEDER_INIT) \
  $(EVENT_LIBS)
#

# fjarcodekernel library #
if BUILD_FJARCODE_KERNEL_LIB
lib_LTLIBRARIES += $(LIBFJARCODEKERNEL)

libfjarcodekernel_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS) $(PTHREAD_FLAGS)
libfjarcodekernel_la_LIBADD = $(LIBFJARCODE_CRYPTO) $(LIBLEVELDB) $(LIBMEMENV) $(LIBSECP256K1)
libfjarcodekernel_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS)

# libfjarcodekernel requires default symbol visibility, explicitly specify that
# here so that things still work even when user configures with
#   --enable-reduce-exports
#
# Note this is a quick hack that will be removed as we incrementally define what
# to export from the library.
libfjarcodekernel_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -fvisibility=default

# TODO: libfjarcodekernel is a work in progress consensus engine library, as more
#       and more modules are decoupled from the consensus engine, this list will
#       shrink to only those which are absolutely necessary.
libfjarcodekernel_la_SOURCES = \
  kernel/fjarcodekernel.cpp \
  arith_uint256.cpp \
  chain.cpp \
  clientversion.cpp \
  coins.cpp \
  compressor.cpp \
  consensus/merkle.cpp \
  consensus/tx_check.cpp \
  consensus/tx_verify.cpp \
  core_read.cpp \
  dbwrapper.cpp \
  deploymentinfo.cpp \
  deploymentstatus.cpp \
  flatfile.cpp \
  hash.cpp \
  kernel/chain.cpp \
  kernel/checks.cpp \
  kernel/chainparams.cpp \
  kernel/coinstats.cpp \
  kernel/context.cpp \
  kernel/cs_main.cpp \
  kernel/disconnected_transactions.cpp \
  kernel/mempool_persist.cpp \
  kernel/mempool_removal_reason.cpp \
  key.cpp \
  logging.cpp \
  node/blockstorage.cpp \
  node/chainstate.cpp \
  node/utxo_snapshot.cpp \
  policy/v3_policy.cpp \
  policy/feerate.cpp \
  policy/packages.cpp \
  policy/policy.cpp \
  policy/rbf.cpp \
  policy/settings.cpp \
  pow.cpp \
  primitives/block.cpp \
  primitives/transaction.cpp \
  pubkey.cpp \
  random.cpp \
  randomenv.cpp \
  scheduler.cpp \
  script/bitfield.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/script_error.cpp \
  script/script_num_encoding.cpp \
  script/scriptcache.cpp \
  script/sigcache.cpp \
  script/solver.cpp \
  signet.cpp \
  streams.cpp \
  support/cleanse.cpp \
  support/lockedpool.cpp \
  sync.cpp \
  txdb.cpp \
  txmempool.cpp \
  uint256.cpp \
  util/batchpriority.cpp \
  util/chaintype.cpp \
  util/check.cpp \
  util/exception.cpp \
  util/fs.cpp \
  util/fs_helpers.cpp \
  util/hasher.cpp \
  util/moneystr.cpp \
  util/rbf.cpp \
  util/serfloat.cpp \
  util/signalinterrupt.cpp \
  util/strencodings.cpp \
  util/string.cpp \
  util/syserror.cpp \
  util/thread.cpp \
  util/threadnames.cpp \
  util/time.cpp \
  util/tokenpipe.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  warnings.cpp

# Required for obj/build.h to be generated first.
# More details: https://www.gnu.org/software/automake/manual/html_node/Built-Sources-Example.html
libfjarcodekernel_la-clientversion.l$(OBJEXT): obj/build.h
endif # BUILD_FJARCODE_KERNEL_LIB
#

# fjarcodeconsensus library #
if BUILD_FJARCODE_LIBS
lib_LTLIBRARIES += $(LIBFJARCODECONSENSUS)

include_HEADERS = script/fjarcodeconsensus.h
libfjarcodeconsensus_la_SOURCES = support/cleanse.cpp $(crypto_libfjarcode_crypto_base_la_SOURCES) $(libfjarcode_consensus_a_SOURCES)

libfjarcodeconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libfjarcodeconsensus_la_LIBADD = $(LIBSECP256K1)
libfjarcodeconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_FJARCODE_INTERNAL -DDISABLE_OPTIMIZED_SHA256
libfjarcodeconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crc32c/src/*.gcda crc32c/src/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += index/*.gcda index/*.gcno
CLEANFILES += interfaces/*.gcda interfaces/*.gcno
CLEANFILES += node/*.gcda node/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += rpc/*.gcda rpc/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += util/*.gcda util/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h

EXTRA_DIST = $(CTAES_DIST)


config/fjarcode-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/fjarcode-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/fjarcode-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/fjarcode-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES) || (echo "windres $(WINDRES) not found, but is required to compile windows resource files"; exit 1)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
	@echo "Running symbol and dynamic library checks..."
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

libfjarcode_ipc_mpgen_input = \
  ipc/capnp/echo.capnp \
  ipc/capnp/init.capnp
EXTRA_DIST += $(libfjarcode_ipc_mpgen_input)
%.capnp:

# Explicitly list dependencies on generated headers as described in
# https://www.gnu.org/software/automake/manual/html_node/Built-Sources-Example.html#Recording-Dependencies-manually
ipc/capnp/libfjarcode_ipc_a-protocol.$(OBJEXT): $(libfjarcode_ipc_mpgen_input:=.h)

if BUILD_MULTIPROCESS
LIBFJARCODE_IPC=libfjarcode_ipc.a
libfjarcode_ipc_a_SOURCES = \
  ipc/capnp/common-types.h \
  ipc/capnp/context.h \
  ipc/capnp/init-types.h \
  ipc/capnp/protocol.cpp \
  ipc/capnp/protocol.h \
  ipc/context.h \
  ipc/exception.h \
  ipc/interfaces.cpp \
  ipc/process.cpp \
  ipc/process.h \
  ipc/protocol.h
libfjarcode_ipc_a_CPPFLAGS = $(AM_CPPFLAGS) $(FJARCODE_INCLUDES)
libfjarcode_ipc_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(LIBMULTIPROCESS_CFLAGS)

include $(MPGEN_PREFIX)/include/mpgen.mk
libfjarcode_ipc_mpgen_output = \
  $(libfjarcode_ipc_mpgen_input:=.c++) \
  $(libfjarcode_ipc_mpgen_input:=.h) \
  $(libfjarcode_ipc_mpgen_input:=.proxy-client.c++) \
  $(libfjarcode_ipc_mpgen_input:=.proxy-server.c++) \
  $(libfjarcode_ipc_mpgen_input:=.proxy-types.c++) \
  $(libfjarcode_ipc_mpgen_input:=.proxy-types.h) \
  $(libfjarcode_ipc_mpgen_input:=.proxy.h)
nodist_libfjarcode_ipc_a_SOURCES = $(libfjarcode_ipc_mpgen_output)
CLEANFILES += $(libfjarcode_ipc_mpgen_output)
endif

%.raw.h: %.raw
	@$(MKDIR_P) $(@D)
	$(AM_V_GEN) { \
	 echo "static unsigned const char $(*F)_raw[] = {" && \
	 $(HEXDUMP) -v -e '8/1 "0x%02x, "' -e '"\n"' $< | $(SED) -e 's/0x  ,//g' && \
	 echo "};"; \
	} > "$@.new" && mv -f "$@.new" "$@"

include Makefile.minisketch.include

include Makefile.crc32c.include
include Makefile.leveldb.include

include Makefile.test_util.include
include Makefile.test_fuzz.include

include Makefile.test.include

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif

include Makefile.univalue.include
