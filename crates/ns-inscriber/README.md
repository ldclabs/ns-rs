# ns-inscriber

More information about the protocol can be found in the [protocol documentation](https://github.com/ldclabs/ns-protocol)

## Development

```sh
cargo run --package ns-inscriber --bin ns-inscriber
```

```sh
cargo build --release --package ns-inscriber --bin ns-inscriber
```

## Usage

Rename `example.env` to `.env` and fill in the values, run ns-inscriber with `.env`:
```sh
./target/release/ns-inscriber help
./target/release/ns-inscriber list-keys
```

run ns-inscriber with `my.env`
```sh
./target/release/ns-inscriber -c my.env list-keys
```

This is the first transaction inscribed NS inscriptions on mainnet:
https://mempool.space/tx/8e9d3e0d762c1d2348a2ca046b36f8de001f740c976b09c046ee1f09a8680131

```sh
ns-inscriber -c my.env inscribe --txid 1d6166ed74982ffd757d3da4082fa18a61094785a3338d6caf3c50190f3e14d7 --addr bc1q6dukpvmcxae0pdh95zgh793l5ept8fluhqqnyc --fee 200 --key 0x31d6ec328b42051a63c1619afad4e60b78f4991e62337918fe2d2e694a4f88f7 --names 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z
```
