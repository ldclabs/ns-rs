CREATE KEYSPACE IF NOT EXISTS ns_indexer
WITH replication = { 'class': 'NetworkTopologyStrategy', 'replication_factor': '3' };
USE ns_indexer;