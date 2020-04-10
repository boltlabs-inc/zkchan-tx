use super::*;
use bitcoin::transaction::BitcoinTransactionParameters;
use bitcoin::{BitcoinPrivateKey, Testnet};
use sha2::{Digest, Sha256};
use transactions::btc::{
    completely_sign_multi_sig_transaction, create_escrow_transaction,
    generate_signature_for_multi_sig_transaction, merch_generate_transaction_id,
    sign_cust_close_claim_transaction, sign_escrow_transaction, sign_merch_dispute_transaction,
};
use transactions::{ChangeOutput, Input, MultiSigOutput, Output};
use wagyu_model::Transaction;

macro_rules! check_pk_length {
    ($x: expr) => {
        if $x.len() != 33 { 
            return Err(format!("{} not a compressed pk", stringify!($x)));
        }
    };
}

#[macro_export]
macro_rules! handle_error {
    ($x: expr) => {
        match $x {
            Ok(n) => n,
            Err(e) => return Err(e.to_string()),
        }
    };
}

pub fn customer_sign_escrow_transaction(
    txid: Vec<u8>,
    index: u32,
    input_sats: i64,
    output_sats: i64,
    cust_sk: Vec<u8>,
    cust_pk: Vec<u8>,
    merch_pk: Vec<u8>,
    change_pk: Option<Vec<u8>>,
    change_pk_is_hash: bool,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32]), String> {
    check_pk_length!(cust_pk);
    check_pk_length!(merch_pk);
    let change_pubkey = match change_pk {
        Some(pk) => match change_pk_is_hash {
            true => pk,
            false => {
                check_pk_length!(pk);
                pk
            }
        },
        None => Vec::new(),
    };

    let input = Input {
        address_format: "p2sh_p2wpkh",
        transaction_id: txid,
        index: index,
        redeem_script: None,
        script_pub_key: None,
        utxo_amount: Some(input_sats), // assumes already in sats
        sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
    };

    let musig_output = MultiSigOutput {
        cust_pubkey: cust_pk,
        merch_pubkey: merch_pk,
        address_format: "p2wsh",
        amount: output_sats, // assumes already in sats
    };

    // test if we need a change output pubkey
    let change_sats = input_sats - output_sats;
    let change_output = match change_sats > 0 && change_pubkey.len() > 0 {
        true => ChangeOutput {
            pubkey: change_pubkey,
            amount: change_sats,
            is_hash: change_pk_is_hash,
        },
        false => {
            return Err(String::from(
                "Require a change pubkey to generate a valid escrow transaction",
            ))
        }
    };

    let csk = handle_error!(SecretKey::parse_slice(&cust_sk));
    let private_key = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&csk, false);
    let (_escrow_tx_preimage, full_escrow_tx) =
        handle_error!(create_escrow_transaction::<Testnet>(
            &input,
            &musig_output,
            &change_output,
            private_key.clone()
        ));
    let (signed_tx, txid, hash_prevout) =
        sign_escrow_transaction::<Testnet>(full_escrow_tx, private_key);

    Ok((signed_tx, txid, hash_prevout))
}

pub fn customer_sign_merch_close_transaction(
    cust_sk: Vec<u8>,
    merch_tx_preimage: Vec<u8>,
) -> Result<Vec<u8>, String> {
    // customer signs the preimage and sends signature to merchant
    let csk = handle_error!(SecretKey::parse_slice(&cust_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&csk, false);
    let cust_sig =
        generate_signature_for_multi_sig_transaction::<Testnet>(&merch_tx_preimage, &sk)?;
    Ok(cust_sig)
}

pub fn merchant_verify_merch_close_transaction(
    merch_tx_preimage: &Vec<u8>,
    cust_sig_and_len_byte: &Vec<u8>,
    cust_pk: &Vec<u8>,
) -> Result<bool, String> {
    let pk = match secp256k1::PublicKey::parse_slice(&cust_pk, None) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string()),
    };
    let merch_tx_hash = Sha256::digest(&Sha256::digest(&merch_tx_preimage));
    let sig_len = cust_sig_and_len_byte[0] as usize;
    let mut new_cust_sig = cust_sig_and_len_byte[1..].to_vec();
    if sig_len != new_cust_sig.len() {
        return Err(String::from("Invalid escrow_sig len!"));
    }
    new_cust_sig.pop(); // remove last byte for sighash flag
                        // now we can check the signature
    let cust_sig = match secp256k1::Signature::parse_der(&new_cust_sig.as_slice()) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string()),
    };
    let msg = secp256k1::Message::parse_slice(&merch_tx_hash).unwrap();
    // let secp = secp256k1::Secp256k1::verification_only();
    let cust_sig_valid = secp256k1::verify(&msg, &cust_sig, &pk);

    Ok(cust_sig_valid)
}

pub fn merchant_generate_transaction_id(
    tx_params: BitcoinTransactionParameters<Testnet>,
) -> Result<([u8; 32], [u8; 32]), String> {
    merch_generate_transaction_id::<Testnet>(tx_params)
}

pub fn merchant_sign_merch_close_transaction(
    tx_params: BitcoinTransactionParameters<Testnet>,
    cust_sig_and_len_byte: Vec<u8>,
    merch_sk: Vec<u8>,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32]), String> {
    // merchant takes as input the tx params and signs it
    let msk = handle_error!(SecretKey::parse_slice(&merch_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&msk, false);
    let (signed_merch_close_tx, txid, hash_prevout) =
        completely_sign_multi_sig_transaction::<Testnet>(
            &tx_params,
            &cust_sig_and_len_byte,
            false,
            None,
            &sk,
        );
    let signed_merch_close_tx = signed_merch_close_tx.to_transaction_bytes().unwrap();

    Ok((signed_merch_close_tx, txid, hash_prevout))
}

pub fn merchant_sign_merch_dispute_transaction(
    txid_le: Vec<u8>,
    index: u32,
    input_sats: i64,
    self_delay_be: [u8; 2],
    output_pk: Vec<u8>,
    rev_lock: Vec<u8>,
    rev_secret: Vec<u8>,
    cust_close_pk: Vec<u8>,
    merch_disp_pk: Vec<u8>,
    merch_sk: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let msk = handle_error!(SecretKey::parse_slice(&merch_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&msk, false);
    let output = Output {
        amount: input_sats,
        pubkey: output_pk,
    };

    let signed_tx = match sign_merch_dispute_transaction::<Testnet>(
        txid_le,
        index,
        output,
        self_delay_be,
        rev_lock,
        rev_secret,
        cust_close_pk,
        merch_disp_pk,
        sk,
    ) {
        Ok(s) => s.0,
        Err(e) => return Err(e.to_string()),
    };
    Ok(signed_tx)
}

pub fn customer_sign_cust_close_claim_transaction(
    txid_le: Vec<u8>,
    index: u32,
    input_sats: i64,
    self_delay_be: [u8; 2],
    output_pk: Vec<u8>,
    rev_lock: Vec<u8>,
    cust_close_pk: Vec<u8>,
    merch_disp_pk: Vec<u8>,
    cust_sk: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let csk = handle_error!(SecretKey::parse_slice(&cust_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&csk, false);
    let output = Output {
        amount: input_sats,
        pubkey: output_pk,
    };

    let signed_tx = match sign_cust_close_claim_transaction::<Testnet>(
        txid_le,
        index,
        output,
        self_delay_be,
        rev_lock,
        merch_disp_pk,
        cust_close_pk,
        sk,
    ) {
        Ok(s) => s.0,
        Err(e) => return Err(e.to_string()),
    };
    Ok(signed_tx)
}

pub fn merchant_sign_cust_close_claim_transaction(
    txid_le: Vec<u8>,
    index: u32,
    input_sats: i64,
    output_pk: Vec<u8>,
    merch_sk: Vec<u8>
) -> Result<Vec<u8>, String> {
    let msk = handle_error!(SecretKey::parse_slice(&merch_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&msk, false);
    let input = Input {
        address_format: "p2wpkh",
        transaction_id: txid_le,
        index: index,
        redeem_script: None,
        script_pub_key: None,
        utxo_amount: Some(input_sats),
        sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
    };

    let output = Output {
        amount: input_sats,
        pubkey: output_pk,
    };

    let signed_tx = match transactions::btc::sign_merch_claim_transaction(
        input,
        output,
        sk,
    ) {
        Ok(s) => s.0,
        Err(e) => return Err(e.to_string())
    };
    Ok(signed_tx)
}

pub fn merchant_sign_merch_close_claim_transaction(
    txid_le: Vec<u8>,
    index: u32,
    input_sats: i64,
    output_pk: Vec<u8>,
    to_self_delay_be: [u8; 2],
    cust_pk: Vec<u8>,
    merch_pk: Vec<u8>,
    merch_close_pk: Vec<u8>,
    merch_close_sk: Vec<u8>
) -> Result<Vec<u8>, String> {
    let merch_csk = handle_error!(SecretKey::parse_slice(&merch_close_sk));    
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&merch_csk, false);
    let mut to_self_delay_le = to_self_delay_be.to_vec();
    to_self_delay_le.reverse();
    
    let redeem_script = transactions::btc::serialize_p2wsh_merch_close_redeem_script(
        &cust_pk,
        &merch_pk,
        &merch_close_pk,
        &to_self_delay_le,
    );
    to_self_delay_le.extend_from_slice(&[0u8; 2]);
    let mut sequence = [0u8; 4];
    sequence.copy_from_slice(to_self_delay_le.as_slice());

    let input = Input {
        address_format: "p2wsh",
        transaction_id: txid_le,
        index: index,
        redeem_script: Some(redeem_script),
        script_pub_key: None,
        utxo_amount: Some(input_sats),
        sequence: Some(sequence),
    };

    let output = Output {
        amount: input_sats,
        pubkey: output_pk,
    };

    let signed_tx = match transactions::btc::sign_merch_claim_transaction(
        input,
        output,
        sk,
    ) {
        Ok(s) => s.0,
        Err(e) => return Err(e.to_string())
    };
    Ok(signed_tx)
}

#[cfg(test)]
mod tests {
    #[test]
    fn check_customer_sign_escrow_transaction() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn check_customer_sign_cust_close_claim_transaction() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn check_customer_sign_merch_close_transaction() {
        assert_eq!(2 + 2, 4);
    }
}
