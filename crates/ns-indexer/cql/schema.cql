CREATE TABLE IF NOT EXISTS name_state (
    name             TEXT,       -- unique name
    sequence         BIGINT,     -- name's latest sequence
    block_height     BIGINT,     -- latest update at block height
    block_time       BIGINT,     -- latest update at block time
    threshold        TINYINT,    -- verifing threshold
    key_kind         TINYINT,    -- int8, 0: Ed25519
    public_keys      LIST<BLOB>, -- public keys
    next_public_keys LIST<BLOB>, -- can be null
    PRIMARY KEY (name)
) WITH caching = {'enabled': 'true'}
    AND comment = 'name state at LastAccepted checkpoint'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE TABLE IF NOT EXISTS name_index (
    name             TEXT,       -- unique name
    block_time       BIGINT,     -- latest update at block time
    PRIMARY KEY (name)
) WITH caching = {'enabled': 'true'}
    AND comment = 'name index'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE TABLE IF NOT EXISTS pubkey_name (
    pubkey   BLOB,  -- public key
    name     TEXT,  -- unique name
    PRIMARY KEY (pubkey, name)
) WITH CLUSTERING ORDER BY (name ASC)
    AND caching = {'enabled': 'true'}
    AND comment = 'public_key to name mapping'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE TABLE IF NOT EXISTS service_state (
    name     TEXT,   -- unique name
    code     BIGINT, -- name's service code
    sequence BIGINT, -- name's latest sequence
    data    BLOB,   -- service state in CBOR format
    PRIMARY KEY (name, code)
) WITH CLUSTERING ORDER BY (code ASC)
    AND caching = {'enabled': 'true'}
    AND comment = 'name service state at LastAccepted checkpoint'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX service_state_code ON service_state (code);

CREATE TABLE IF NOT EXISTS service_protocol (
    code      BIGINT, -- service code
    version   INT,    -- protocol version
    protocol  BLOB,   -- protocol in CBOR schema
    submitter TEXT,   -- submitter's name
    sequence  BIGINT, -- submitter's updating sequence
    PRIMARY KEY (code, version)
) WITH CLUSTERING ORDER BY (version DESC)
    AND caching = {'enabled': 'true'}
    AND comment = 'available service protocols'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX service_protocol_submitter ON service_protocol (submitter);

CREATE TABLE IF NOT EXISTS inscription (
    name          TEXT,      -- unique name
    sequence      BIGINT,    -- name's updating sequence
    height        BIGINT,    -- inscription's global height
    previous_hash BLOB,      -- previous inscription hash
    name_hash     BLOB,      -- current name state hash
    service_hash  BLOB,      -- current service state hash
    protocol_hash BLOB,      -- service protocol hash if inscription contains service protocol
    block_hash    BLOB,      -- block hash that contains this inscription
    block_height  BIGINT,    -- block height
    txid          BLOB,      -- transaction id that contains this inscription
    vin           TINYINT,   -- input index in transaction that contains this inscription
    data          BLOB,      -- name item in CBOR format
    PRIMARY KEY (name, sequence)
) WITH CLUSTERING ORDER BY (sequence DESC)
    AND caching = {'enabled': 'true'}
    AND comment = 'inscription logs'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX inscription_height ON inscription (height);
CREATE INDEX inscription_block_height ON inscription (block_height);

CREATE TABLE IF NOT EXISTS invalid_inscription (
    name           TEXT,      -- name in this invalid inscription
    block_height   BIGINT,    -- block height that contains this invalid inscription
    hash           BLOB,      -- name item hash
    reason         TEXT,      -- reason of invalid
    data           BLOB,      -- name item in CBOR format
    PRIMARY KEY (name, block_height, hash)
) WITH CLUSTERING ORDER BY (block_height DESC, hash ASC)
    AND caching = {'enabled': 'true'}
    AND comment = 'invalid inscriptions'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 2592000; -- 30 days

CREATE INDEX invalid_inscription_block_height ON invalid_inscription (block_height);

CREATE TABLE IF NOT EXISTS checkpoint (
    checkpoint   TEXT,      -- only two: "LastAccepted", "LastAcceptedHeight"
    block_height BIGINT,    -- block height
    height       BIGINT,    -- the last inscription height at this checkpoint
    hash         BLOB,      -- the last inscription hash at this checkpoint
    name         TEXT,      -- name in the last inscription
    sequence     BIGINT,    -- sequence in the last inscription
    PRIMARY KEY (checkpoint)
) WITH caching = {'enabled': 'true'}
    AND comment = 'checkpoints'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE TABLE IF NOT EXISTS utxo (
    txid          BLOB,    -- transaction id that contains this inscription
    vout          INT,     -- output index in transaction
    amount        BIGINT,  -- unspend amount in satoshi
    address       BLOB,    -- p2tr address
    PRIMARY KEY (txid, vout)
) WITH CLUSTERING ORDER BY (vout ASC)
    AND caching = {'enabled': 'true'}
    AND comment = 'unspent TX outputs'
    AND compaction = {'class': 'SizeTieredCompactionStrategy'}
    AND compression = {'sstable_compression': 'LZ4Compressor'}
    AND default_time_to_live = 0;

CREATE INDEX utxo_address ON utxo (address);