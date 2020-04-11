extern crate hex;
extern crate serde;
extern crate wagyu_bitcoin as bitcoin;
extern crate wagyu_model;

pub mod fixed_size_array;
pub mod transactions;
pub mod txutil;

use secp256k1::{sign, verify, Message, PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    //use secp256k1::{PublicKey, SecretKey};
    //use sha2::{Digest, Sha256};

    /*
    #[test]
    fn test_serialize() {
        let key = [1u8; 32];
        let seckey = SecretKey::parse_slice(&key).unwrap();
        let pubkey = PublicKey::from_secret_key(&seckey);

        // let t = TestSecp { a: pubkey };
        //let s = serde_json::to_string(&pubkey).unwrap();

        // println!("Ser pubkey: {:?}", pubkey);

        assert_eq!(2 + 2, 4);
    }
    */
}
