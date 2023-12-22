CREATE KEYSPACE IF NOT EXISTS ns_indexer
WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': 1 };
USE ns_indexer;
