# zkchan-tx

<a href="https://travis-ci.com/github/boltlabs-inc/zkchan-tx"><img src="https://travis-ci.com/boltlabs-inc/zkchan-tx.svg?branch=master"></a>

# Overview

Using the wagyu library, this project provides a transaction builder for the [zkChannels](https://github.com/boltlabs-inc/libzkchannels) protocol to support Bitcoin, Zcash and other cryptocurrencies. The transactions cover all aspects of zkChannels which includes constructing the funding/escrow and closing transactions. In addition, transactions for disputing and claiming the funds from a closed channel after the dispute period.

# Dependencies

We rely on the following dependencies:

* libsecp256k1
* serde
* [wagyu](https://github.com/AleoHQ/wagyu)

# Usage

To use `zkchan-tx` library, add the `zkchan-tx` crate to your dependency file in `Cargo.toml` as follows:

```toml
[dependencies]
zkchan-tx = { git = "https://github.com/boltlabs-inc/zkchan-tx" }
```

Then add an extern declaration at the root of your crate as follows:
```rust
extern crate zkchan_tx;
```

# License

MIT License