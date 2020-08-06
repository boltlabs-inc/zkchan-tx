use super::*;
use crate::wagyu_model::{PrivateKey, Transaction};
use bitcoin::transaction::BitcoinTransactionParameters;
use bitcoin::{BitcoinAddress, BitcoinPrivateKey, BitcoinPublicKey, Testnet};
use sha2::{Digest, Sha256};
use transactions::btc::{
    completely_sign_multi_sig_transaction, compute_transaction_id_without_witness,
    create_escrow_transaction, encode_public_key_for_transaction,
    generate_signature_for_multi_sig_transaction, get_private_key, merch_generate_transaction_id,
    sign_child_transaction_helper, sign_cust_close_claim_transaction_helper,
    sign_escrow_transaction, sign_merch_claim_transaction_helper,
    sign_merch_dispute_transaction_helper,
};
use transactions::{ChangeOutput, MultiSigOutput, Output, UtxoInput};

macro_rules! check_pk_length {
    ($x: expr) => {
        if $x.len() != 33 {
            return Err(format!("{} not a compressed pubkey", stringify!($x)));
        }
    };
}

macro_rules! check_sk_length {
    ($x: expr) => {
        if $x.len() != 32 {
            return Err(format!(
                "{} is not a seckey (need 32 bytes)",
                stringify!($x)
            ));
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

// form the escrow transaction given utxo/sk to obtain txid/prevout
pub fn customer_form_escrow_transaction(
    txid_le: &Vec<u8>,
    index: u32,
    cust_input_sk: &Vec<u8>,
    input_sats: i64,
    output_sats: i64,
    cust_pk: &Vec<u8>,
    merch_pk: &Vec<u8>,
    change_pk: Option<&Vec<u8>>,
    change_pk_is_hash: bool,
    tx_fee: i64,
) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    check_sk_length!(cust_input_sk);
    check_pk_length!(cust_pk);
    check_pk_length!(merch_pk);
    let change_pubkey = match change_pk {
        Some(pk) => match change_pk_is_hash {
            true => pk.clone(),
            false => {
                check_pk_length!(pk);
                pk.clone()
            }
        },
        None => Vec::new(),
    };

    if output_sats > (input_sats + tx_fee) {
        return Err(format!("output_sats should be less than input_sats"));
    }

    let input_index = index as usize;
    let cust_input = UtxoInput {
        address_format: String::from("p2sh_p2wpkh"),
        transaction_id: txid_le.clone(),
        index: index,
        redeem_script: None,
        script_pub_key: None,
        utxo_amount: Some(input_sats), // assumes already in sats
        sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
    };

    let musig_output = MultiSigOutput {
        cust_pubkey: cust_pk.clone(),
        merch_pubkey: merch_pk.clone(),
        address_format: "p2wsh",
        amount: output_sats, // assumes already in sats
    };

    // test if we need a change output pubkey
    let change_sats = match tx_fee > 0 {
        true => input_sats - output_sats - tx_fee,
        false => input_sats - output_sats,
    };
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
    let csk = handle_error!(SecretKey::parse_slice(&cust_input_sk));
    let private_key = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&csk, false);
    let cust_input_pk = private_key
        .to_public_key()
        .to_secp256k1_public_key()
        .serialize_compressed()
        .to_vec();

    let cust_utxo = txutil::create_transaction_input(&cust_input, &cust_input_pk).unwrap();

    let (_escrow_tx_preimage, unsigned_escrow_tx) = handle_error!(
        transactions::btc::form_single_escrow_transaction::<Testnet>(
            &vec![cust_utxo],
            input_index,
            &musig_output,
            &change_output
        )
    );

    let (txid_be, txid_le, hash_prevout) = handle_error!(compute_transaction_id_without_witness::<
        Testnet,
    >(unsigned_escrow_tx, private_key));

    Ok((txid_be, txid_le, hash_prevout))
}

// sign the escrow transaction given utxo/sk and can broadcast
pub fn customer_sign_escrow_transaction(
    txid: &Vec<u8>,
    index: u32,
    cust_input_sk: &Vec<u8>,
    input_sats: i64,
    output_sats: i64,
    cust_pk: &Vec<u8>,
    merch_pk: &Vec<u8>,
    change_pk: Option<&Vec<u8>>,
    change_pk_is_hash: bool,
    tx_fee: i64,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32], [u8; 32]), String> {
    check_sk_length!(cust_input_sk);
    check_pk_length!(cust_pk);
    check_pk_length!(merch_pk);
    let change_pubkey = match change_pk {
        Some(pk) => match change_pk_is_hash {
            true => pk.clone(),
            false => {
                check_pk_length!(pk);
                pk.clone()
            }
        },
        None => Vec::new(),
    };

    if output_sats > (input_sats + tx_fee) {
        return Err(format!("output_sats should be less than input_sats"));
    }

    let input_index = 0;
    let input = UtxoInput {
        address_format: String::from("p2sh_p2wpkh"),
        transaction_id: txid.clone(),
        index: index,
        redeem_script: None,
        script_pub_key: None,
        utxo_amount: Some(input_sats), // assumes already in sats
        sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
    };

    let musig_output = MultiSigOutput {
        cust_pubkey: cust_pk.clone(),
        merch_pubkey: merch_pk.clone(),
        address_format: "p2wsh",
        amount: output_sats, // assumes already in sats
    };

    // test if we need a change output pubkey
    let change_sats = match tx_fee > 0 {
        true => input_sats - output_sats - tx_fee,
        false => input_sats - output_sats,
    };
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

    let csk = handle_error!(SecretKey::parse_slice(&cust_input_sk));
    let private_key = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&csk, false);
    let (_escrow_tx_preimage, full_escrow_tx) =
        handle_error!(create_escrow_transaction::<Testnet>(
            &input,
            input_index,
            &musig_output,
            &change_output,
            private_key.clone()
        ));
    let (signed_tx, txid_be, hash_prevout) =
        sign_escrow_transaction::<Testnet>(full_escrow_tx, private_key);
    let mut txid_le = txid_be.clone();
    txid_le.reverse();
    Ok((signed_tx, txid_be, txid_le, hash_prevout))
}

pub fn create_transaction_input(
    utxo: &UtxoInput,
    utxo_pk: &Vec<u8>,
) -> Result<BitcoinTransactionInput<Testnet>, String> {
    check_pk_length!(utxo_pk);
    // convert pk into public key
    let pubkey = handle_error!(PublicKey::parse_slice(utxo_pk, None));

    let address_format = match utxo.address_format.as_str() {
        "p2pkh" => BitcoinFormat::Bech32,
        "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
        _ => {
            return Err(format!(
                "do not currently support specified address format as funding input: {}",
                utxo.address_format
            ))
        }
    };

    let public_key = BitcoinPublicKey::<Testnet>::from_secp256k1_public_key(pubkey, true);
    let address = match address_format {
        BitcoinFormat::P2SH_P2WPKH => BitcoinAddress::<Testnet>::p2sh_p2wpkh(&public_key).unwrap(),
        BitcoinFormat::Bech32 => BitcoinAddress::<Testnet>::p2pkh(&public_key).unwrap(),
        _ => return Err(format!("address format not supported")),
    };

    let utxo_input =
        transactions::btc::form_transaction_input::<Testnet>(&utxo, &address, &utxo_pk).unwrap();

    Ok(utxo_input)
}

#[derive(Clone, Debug, PartialEq, Hash)]
pub struct EscrowTx {
    pub txid_be: [u8; 32],
    pub txid_le: [u8; 32],
    pub prevout: [u8; 32],
    pub cust_signature: Vec<u8>,
    pub cust_pubkey: Vec<u8>,
}

// form the dual funded escrow tx and get the UTXOs
pub fn customer_sign_dual_escrow_transaction(
    cust_utxo: &BitcoinTransactionInput<Testnet>,
    merch_utxo: &BitcoinTransactionInput<Testnet>,
    cust_funding_sats: i64,
    merch_funding_sats: i64,
    cust_pk: &Vec<u8>,
    merch_pk: &Vec<u8>,
    cust_change_pk: Option<(Vec<u8>, bool)>,
    merch_change_pk: Option<(Vec<u8>, bool)>,
    cust_utxo_sk: Option<(Vec<u8>, BitcoinFormat)>,
) -> Result<EscrowTx, String> {
    // get initial utxo amounts
    let cust_bal_utxo = cust_utxo.outpoint.amount.unwrap();
    let merch_bal_utxo = merch_utxo.outpoint.amount.unwrap();

    // total amount available by both utxos from customer/merchant
    let total_available_balance = cust_bal_utxo.0 + merch_bal_utxo.0;
    // amount being locked up in escrow
    let locked_up_sats = cust_funding_sats + merch_funding_sats;
    if locked_up_sats > total_available_balance {
        return Err(format!("Insufficient funds to create escrow transaction"));
    }

    let ret_cust_bal = cust_bal_utxo.0 - cust_funding_sats;
    let ret_merch_bal = merch_bal_utxo.0 - merch_funding_sats;

    let musig_output = MultiSigOutput {
        cust_pubkey: cust_pk.clone(),
        merch_pubkey: merch_pk.clone(),
        address_format: "p2wsh",
        amount: locked_up_sats,
    };

    let mut change_outputs = vec![];

    // check if customer requires a change-pk
    if ret_cust_bal != 0 && cust_change_pk.is_none() {
        return Err(format!(
            "Did not specify a change PK for change: {}",
            ret_cust_bal
        ));
    } else if ret_cust_bal > 0 && cust_change_pk.is_some() {
        // test if we need a change output pubkey
        let (change_pubkey, change_pk_is_hash) = cust_change_pk.unwrap();
        check_pk_length!(change_pubkey);
        let change_output = ChangeOutput {
            pubkey: change_pubkey,
            amount: ret_cust_bal,
            is_hash: change_pk_is_hash,
        };
        change_outputs.push(change_output);
    }

    // check if merchant requires a change-pk
    if ret_merch_bal != 0 && merch_change_pk.is_none() {
        return Err(format!(
            "Did not specify a change PK for change: {}",
            ret_cust_bal
        ));
    } else if ret_merch_bal > 0 && merch_change_pk.is_some() {
        // test if we need a change output pubkey
        let (change_pubkey, change_pk_is_hash) = merch_change_pk.unwrap();
        check_pk_length!(change_pubkey);
        let change_output = ChangeOutput {
            pubkey: change_pubkey,
            amount: ret_merch_bal,
            is_hash: change_pk_is_hash,
        };
        change_outputs.push(change_output);
    }

    // test forming tx preimage for customer side
    let inputs = vec![cust_utxo.clone(), merch_utxo.clone()];
    let (tx_preimage, cust_tx) =
        transactions::btc::form_dual_escrow_transaction(&inputs, 0, &musig_output, &change_outputs)
            .unwrap();
    // println!("=================================================");
    // println!("Cust Tx preimage 1: {}", hex::encode(&tx_preimage));
    // println!("=================================================");

    let (sk, address_format) = cust_utxo_sk.unwrap();
    let private_key = match get_private_key::<Testnet>(&sk) {
        Ok(p) => p,
        Err(e) => return Err(e.to_string()),
    };

    let signed_cust_tx = cust_tx.sign(&private_key).unwrap();
    let tx_id_hex = signed_cust_tx.to_transaction_id().unwrap();

    let txid = hex::decode(tx_id_hex.to_string()).unwrap();
    let mut txid_buf = [0u8; 32];
    let mut hash_prevout = [0u8; 32];
    txid_buf.copy_from_slice(txid.as_slice());
    let mut txid_buf_be = txid_buf.clone();
    txid_buf_be.reverse();
    let txid_buf_le = txid_buf.clone();

    let mut prevout_preimage: Vec<u8> = Vec::new();
    prevout_preimage.extend(txid_buf_be.iter()); // txid (big endian)
    prevout_preimage.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
    let result = Sha256::digest(&Sha256::digest(&prevout_preimage));
    hash_prevout.copy_from_slice(&result);

    // generate the signature on preimage and encode the public key
    let cust_signature =
        generate_signature_for_multi_sig_transaction::<Testnet>(&tx_preimage, &private_key)
            .unwrap();

    // encode the public key
    let cust_pubkey = encode_public_key_for_transaction::<Testnet>(address_format, &private_key);

    let escrow_tx = EscrowTx {
        txid_be: txid_buf_be,
        txid_le: txid_buf_le,
        prevout: hash_prevout,
        cust_signature: cust_signature,
        cust_pubkey: cust_pubkey,
    };

    Ok(escrow_tx)
}

pub fn merchant_sign_dual_escrow_transaction(
    cust_utxo: &BitcoinTransactionInput<Testnet>,
    merch_utxo: &BitcoinTransactionInput<Testnet>,
    cust_witness_sig: &Vec<u8>,
    cust_witness_pk: &Vec<u8>,
    cust_funding_sats: i64,
    merch_funding_sats: i64,
    cust_pk: &Vec<u8>,
    merch_pk: &Vec<u8>,
    cust_change_pk: Option<(Vec<u8>, bool)>,
    merch_change_pk: Option<(Vec<u8>, bool)>,
    merch_sk: &Vec<u8>,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32], [u8; 32]), String> {
    let cust_bal_utxo = cust_utxo.outpoint.amount.unwrap();
    let merch_bal_utxo = merch_utxo.outpoint.amount.unwrap();

    // total amount available by both utxos from customer/merchant
    let total_available_balance = cust_bal_utxo.0 + merch_bal_utxo.0;
    // amount being locked up in escrow
    let locked_up_sats = cust_funding_sats + merch_funding_sats;
    if locked_up_sats > total_available_balance {
        return Err(format!("Insufficient funds to create escrow transaction"));
    }

    let ret_cust_bal = cust_bal_utxo.0 - cust_funding_sats;
    let ret_merch_bal = merch_bal_utxo.0 - merch_funding_sats;

    let musig_output = MultiSigOutput {
        cust_pubkey: cust_pk.clone(),
        merch_pubkey: merch_pk.clone(),
        address_format: "p2wsh",
        amount: locked_up_sats,
    };

    let mut change_outputs = vec![];

    // check if customer requires a change-pk
    if ret_cust_bal != 0 && cust_change_pk.is_none() {
        return Err(format!(
            "Did not specify a change PK for change: {}",
            ret_cust_bal
        ));
    } else if ret_cust_bal > 0 && cust_change_pk.is_some() {
        // test if we need a change output pubkey
        let (change_pubkey, change_pk_is_hash) = cust_change_pk.unwrap();
        check_pk_length!(change_pubkey);
        let change_output = ChangeOutput {
            pubkey: change_pubkey,
            amount: ret_cust_bal,
            is_hash: change_pk_is_hash,
        };
        change_outputs.push(change_output);
    }

    // check if merchant requires a change-pk
    if ret_merch_bal != 0 && merch_change_pk.is_none() {
        return Err(format!(
            "Did not specify a change PK for change: {}",
            ret_cust_bal
        ));
    } else if ret_merch_bal > 0 && merch_change_pk.is_some() {
        // test if we need a change output pubkey
        let (change_pubkey, change_pk_is_hash) = merch_change_pk.unwrap();
        check_pk_length!(change_pubkey);
        let change_output = ChangeOutput {
            pubkey: change_pubkey,
            amount: ret_merch_bal,
            is_hash: change_pk_is_hash,
        };
        change_outputs.push(change_output);
    }

    // first verify the signature with respect to the cust_tx_preimage
    let (cust_tx_preimage, _) = transactions::btc::form_dual_escrow_transaction(
        &vec![cust_utxo.clone(), merch_utxo.clone()],
        0,
        &musig_output,
        &change_outputs,
    )
    .unwrap();
    // println!("=================================================");
    // println!("Cust Tx preimage 2: {}", hex::encode(&cust_tx_preimage));
    // println!("=================================================");

    // parse the sig/pk accordingly
    let witness_pk = PublicKey::parse_slice(&cust_witness_pk[1..], None).unwrap();
    let escrow_tx_hash = Sha256::digest(&Sha256::digest(&cust_tx_preimage));
    let msg = secp256k1::Message::parse_slice(&escrow_tx_hash).unwrap();
    let mut cust_sig = cust_witness_sig.clone();
    cust_sig.pop();
    let sig = secp256k1::Signature::parse_der(&cust_sig[1..]).unwrap();
    // verify that the cust-signature is valid w.r.t preimage
    if !verify(&msg, &sig, &witness_pk) {
        return Err(format!(
            "Could not validate signature on <cust-tx-preimage> for dual-funded escrow tx"
        ));
    }

    // add signature/pubkey to cust_utxo before signing
    let mut cust_tx_input = cust_utxo.clone();
    cust_tx_input
        .witnesses
        .append(&mut vec![cust_witness_sig.clone(), cust_witness_pk.clone()]);
    let input_script = match &cust_tx_input.outpoint.redeem_script {
        Some(redeem_script) => redeem_script.clone(),
        None => panic!("Invalid input_script!"),
    };
    cust_tx_input.script_sig = [vec![input_script.len() as u8], input_script].concat();
    cust_tx_input.is_signed = true;

    // include updated cust_tx_input (with witness)
    let input_vec = vec![cust_tx_input.clone(), merch_utxo.clone()];

    // merchant moves forward to sign their UTXO as well
    let (_, escrow_unsigned_tx) = transactions::btc::form_dual_escrow_transaction(
        &input_vec,
        1,
        &musig_output,
        &change_outputs,
    )
    .unwrap();
    // println!("=================================================");
    // println!("Merch Tx preimage: {}", hex::encode(&merch_tx_preimage));
    // println!("=================================================");

    let merch_private_key = match get_private_key::<Testnet>(&merch_sk) {
        Ok(p) => p,
        Err(e) => return Err(e.to_string()),
    };
    let signed_escrow_tx = escrow_unsigned_tx.sign(&merch_private_key).unwrap();

    let signed_tx = signed_escrow_tx.to_transaction_bytes().unwrap();
    let tx_id_hex = signed_escrow_tx.to_transaction_id().unwrap();
    let txid = hex::decode(tx_id_hex.to_string()).unwrap();

    let mut txid_buf = [0u8; 32];
    let mut hash_prevout = [0u8; 32];
    txid_buf.copy_from_slice(txid.as_slice());
    let mut txid_buf_be = txid_buf.clone();
    txid_buf_be.reverse();
    let txid_buf_le = txid_buf.clone();

    let mut prevout_preimage: Vec<u8> = Vec::new();
    prevout_preimage.extend(txid_buf_be.iter()); // txid (big endian)
    prevout_preimage.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
    let result = Sha256::digest(&Sha256::digest(&prevout_preimage));
    hash_prevout.copy_from_slice(&result);

    Ok((signed_tx, txid_buf_be, txid_buf_le, hash_prevout))
}

pub fn customer_sign_merch_close_transaction(
    cust_sk: &Vec<u8>,
    merch_tx_preimage: &Vec<u8>,
) -> Result<Vec<u8>, String> {
    check_sk_length!(cust_sk);
    // customer signs the preimage and sends signature to merchant
    let csk = handle_error!(SecretKey::parse_slice(cust_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&csk, false);
    let cust_sig = generate_signature_for_multi_sig_transaction::<Testnet>(merch_tx_preimage, &sk)?;
    Ok(cust_sig)
}

pub fn merchant_verify_merch_close_transaction(
    merch_tx_preimage: &Vec<u8>,
    cust_sig_and_len_byte: &Vec<u8>,
    cust_pk: &Vec<u8>,
) -> Result<bool, String> {
    check_pk_length!(cust_pk);
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
    check_sk_length!(merch_sk);
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
    output_sats: i64,
    self_delay_be: [u8; 2],
    output_pk: Vec<u8>,
    rev_lock: Vec<u8>,
    rev_secret: Vec<u8>,
    cust_close_pk: Vec<u8>,
    merch_disp_pk: Vec<u8>,
    merch_sk: Vec<u8>,
) -> Result<Vec<u8>, String> {
    check_sk_length!(merch_sk);
    check_pk_length!(cust_close_pk);
    check_pk_length!(merch_disp_pk);

    let msk = handle_error!(SecretKey::parse_slice(&merch_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&msk, false);
    if output_sats > input_sats {
        return Err(format!("output_sats should be less than input_sats"));
    }
    // create txOut
    let output = Output {
        amount: output_sats,
        pubkey: output_pk,
    };
    // create the rest of the transaction
    let signed_tx = match sign_merch_dispute_transaction_helper::<Testnet>(
        txid_le,
        index,
        input_sats,
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
    output_sats: i64,
    self_delay_be: [u8; 2],
    output_pk: Vec<u8>,
    rev_lock: Vec<u8>,
    cust_close_pk: Vec<u8>,
    merch_disp_pk: Vec<u8>,
    cust_sk: Vec<u8>,
) -> Result<Vec<u8>, String> {
    check_sk_length!(cust_sk);
    check_pk_length!(cust_close_pk);
    check_pk_length!(merch_disp_pk);
    let csk = handle_error!(SecretKey::parse_slice(&cust_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&csk, false);
    if output_sats > input_sats {
        return Err(format!("output_sats should be less than input_sats"));
    }
    // create txOut
    let output = Output {
        amount: output_sats,
        pubkey: output_pk,
    };

    // create rest of the transaction
    let signed_tx = match sign_cust_close_claim_transaction_helper::<Testnet>(
        txid_le,
        index,
        input_sats,
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
    output_sats: i64,
    output_pk: Vec<u8>,
    merch_sk: Vec<u8>,
) -> Result<Vec<u8>, String> {
    check_sk_length!(merch_sk);
    check_pk_length!(output_pk);
    let msk = handle_error!(SecretKey::parse_slice(&merch_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&msk, false);
    if output_sats > input_sats {
        return Err(format!("output_sats should be less than input_sats"));
    }

    let input = UtxoInput {
        address_format: String::from("p2wpkh"),
        transaction_id: txid_le,
        index: index,
        redeem_script: None,
        script_pub_key: None,
        utxo_amount: Some(input_sats),
        sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
    };

    let output = Output {
        amount: output_sats,
        pubkey: output_pk,
    };

    let signed_tx = match sign_merch_claim_transaction_helper(input, output, sk) {
        Ok(s) => s.0,
        Err(e) => return Err(e.to_string()),
    };
    Ok(signed_tx)
}

pub fn merchant_sign_merch_close_claim_transaction(
    txid_le: Vec<u8>,
    index: u32,
    input_sats: i64,
    output_sats: i64,
    output_pk: Vec<u8>,
    to_self_delay_be: [u8; 2],
    cust_pk: Vec<u8>,
    merch_pk: Vec<u8>,
    merch_close_pk: Vec<u8>,
    merch_close_sk: Vec<u8>,
) -> Result<Vec<u8>, String> {
    check_pk_length!(merch_pk);
    check_pk_length!(merch_close_pk);
    check_sk_length!(merch_close_sk);
    let merch_csk = handle_error!(SecretKey::parse_slice(&merch_close_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&merch_csk, false);

    let mut to_self_delay_le = to_self_delay_be.to_vec();
    to_self_delay_le.reverse();

    let redeem_script = transactions::btc::serialize_p2wsh_merch_close_redeem_script(
        &cust_pk,
        &merch_pk,
        &merch_close_pk,
        &to_self_delay_le,
    )?;
    to_self_delay_le.extend_from_slice(&[0u8; 2]);
    let mut sequence = [0u8; 4];
    sequence.copy_from_slice(to_self_delay_le.as_slice());

    let input = UtxoInput {
        address_format: String::from("p2wsh"),
        transaction_id: txid_le,
        index: index,
        redeem_script: Some(redeem_script),
        script_pub_key: None,
        utxo_amount: Some(input_sats),
        sequence: Some(sequence),
    };

    let output = Output {
        amount: output_sats,
        pubkey: output_pk,
    };

    let signed_tx = match sign_merch_claim_transaction_helper(input, output, sk) {
        Ok(s) => s.0,
        Err(e) => return Err(e.to_string()),
    };
    Ok(signed_tx)
}

pub fn customer_sign_mutual_close_transaction(
    escrow_input: &UtxoInput,
    cust_pk: &Vec<u8>,
    merch_pk: &Vec<u8>,
    cust_close_pk: &Vec<u8>,
    merch_close_pk: &Vec<u8>,
    cust_bal: i64,
    merch_bal: i64,
    cust_sk: &Vec<u8>,
) -> Result<Vec<u8>, String> {
    check_pk_length!(cust_pk);
    check_pk_length!(cust_close_pk);
    check_pk_length!(merch_pk);
    check_pk_length!(merch_close_pk);
    check_sk_length!(cust_sk);
    let csk = handle_error!(SecretKey::parse_slice(&cust_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&csk, false);

    let (mutual_tx_preimage, _, _) = transactions::btc::create_mutual_close_transaction::<Testnet>(
        &escrow_input,
        &cust_pk,
        &merch_pk,
        &cust_close_pk,
        &merch_close_pk,
        cust_bal,
        merch_bal,
    )
    .unwrap();

    // get the signature on the preimage
    let cust_signature =
        transactions::btc::generate_signature_for_multi_sig_transaction::<Testnet>(
            &mutual_tx_preimage,
            &sk,
        )
        .unwrap();

    return Ok(cust_signature);
}

pub fn merchant_sign_mutual_close_transaction(
    escrow_input: &UtxoInput,
    cust_pk: &Vec<u8>,
    merch_pk: &Vec<u8>,
    cust_close_pk: &Vec<u8>,
    merch_close_pk: &Vec<u8>,
    cust_bal: i64,
    merch_bal: i64,
    cust_signature: &Vec<u8>,
    merch_sk: &Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    check_pk_length!(cust_pk);
    check_pk_length!(cust_close_pk);
    check_pk_length!(merch_pk);
    check_pk_length!(merch_close_pk);
    check_sk_length!(merch_sk);
    let msk = handle_error!(SecretKey::parse_slice(&merch_sk));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&msk, false);

    let (mutual_tx_preimage, mutual_tx_params, _) =
        transactions::btc::create_mutual_close_transaction::<Testnet>(
            &escrow_input,
            &cust_pk,
            &merch_pk,
            &cust_close_pk,
            &merch_close_pk,
            cust_bal,
            merch_bal,
        )
        .unwrap();

    // check the cust_signature against the mutual_tx_preimage
    let witness_pk = PublicKey::parse_slice(&cust_pk, None).unwrap();
    let escrow_tx_hash = Sha256::digest(&Sha256::digest(&mutual_tx_preimage));
    let msg = secp256k1::Message::parse_slice(&escrow_tx_hash).unwrap();
    let mut cust_sig = cust_signature.clone();
    cust_sig.pop();
    let sig = secp256k1::Signature::parse_der(&cust_sig[1..]).unwrap();
    // verify that the cust-signature is valid w.r.t preimage
    if !verify(&msg, &sig, &witness_pk) {
        return Err(format!(
            "Could not validate signature on <mutual-tx-preimage> for mutual close tx"
        ));
    }

    // merchant completes the signature
    let (signed_mutual_close_tx, txid_be, _) =
        transactions::btc::completely_sign_multi_sig_transaction::<Testnet>(
            &mutual_tx_params,
            &cust_signature,
            false,
            None,
            &sk,
        );
    let signed_tx = signed_mutual_close_tx.to_transaction_bytes().unwrap();
    let mut txid_le = txid_be.to_vec();
    txid_le.reverse();
    return Ok((signed_tx, txid_le));
}

pub fn create_child_transaction(
    txid_le: Vec<u8>,
    index: u32,
    input_sats: i64,
    output_sats: i64,
    output_pk: &Vec<u8>,
    private_key: &Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    check_sk_length!(private_key);
    check_pk_length!(output_pk);
    let the_sk = handle_error!(SecretKey::parse_slice(&private_key));
    let sk = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(&the_sk, false);
    if output_sats > input_sats {
        return Err(format!("output_sats should be less than input_sats"));
    }

    let input = UtxoInput {
        address_format: String::from("p2wpkh"),
        transaction_id: txid_le,
        index: index,
        redeem_script: None,
        script_pub_key: None,
        utxo_amount: Some(input_sats),
        sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
    };

    let output = Output {
        amount: output_sats,
        pubkey: output_pk.clone(),
    };

    let (signed_tx, txid) = handle_error!(sign_child_transaction_helper(input, output, &sk));
    Ok((signed_tx, txid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wagyu_model::PrivateKey;
    use bitcoin::{BitcoinPrivateKey, Testnet};
    use std::str::FromStr;
    use transactions::{UtxoInput, SATOSHI};

    fn get_helper_utxo() -> (Vec<u8>, Vec<u8>) {
        let cust_private_key = BitcoinPrivateKey::<Testnet>::from_str(
            "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn",
        )
        .unwrap();
        let cust_input_sk =
            hex::decode("4157697b6428532758a9d0f9a73ce58befe3fd665797427d1c5bb3d33f6a132e")
                .unwrap();
        let cust_input_pk = cust_private_key
            .to_public_key()
            .to_secp256k1_public_key()
            .serialize_compressed()
            .to_vec();
        assert_eq!(
            cust_input_pk,
            hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb")
                .unwrap()
        );

        return (cust_input_pk, cust_input_sk);
    }

    #[test]
    fn form_single_escrow_transaction() {
        // create customer utxo input
        let txid = hex::decode("d21502c0d197e86b2847ff4c275ae989e06a52f09d60425701c2908217444326")
            .unwrap();
        let index = 0;

        // customer's keypair for utxo
        let (_, cust_input_sk) = get_helper_utxo();

        let good_input_sats = 3 * SATOSHI;
        let bad_input_sats = 2 * SATOSHI;
        let output_sats = 2 * SATOSHI;
        let tx_fee = 1000;
        let cust_pk =
            hex::decode("0250a33b5a379c2143c7deb27345a4f16d6f766fbf31c4a477e64050b5ec506f03")
                .unwrap();
        let merch_pk =
            hex::decode("021df2e472ce4f5f76100a45f04f75bf8742a796a07a6abfc8ed2b9939588b981a")
                .unwrap();
        let change_pk =
            hex::decode("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")
                .unwrap();
        let change_pk_is_hash = false;

        let (txid_be, txid_le, prevout) = customer_form_escrow_transaction(
            &txid,
            index,
            &cust_input_sk,
            good_input_sats,
            output_sats,
            &cust_pk,
            &merch_pk,
            Some(&change_pk),
            change_pk_is_hash,
            tx_fee,
        )
        .unwrap();

        println!("forming the escrow tx: ");
        println!("txid BE: {}", hex::encode(&txid_be));
        println!("txid LE: {}", hex::encode(&txid_le));
        println!("hash prevout: {}", hex::encode(&prevout));

        let (signed_tx, txid2_be, txid2_le, prevout2) = customer_sign_escrow_transaction(
            &txid,
            index,
            &cust_input_sk,
            good_input_sats,
            output_sats,
            &cust_pk,
            &merch_pk,
            Some(&change_pk),
            change_pk_is_hash,
            tx_fee,
        )
        .unwrap();
        assert_eq!(txid_le, txid2_le);
        assert_eq!(txid_be, txid2_be);
        assert_eq!(prevout, prevout2);
        println!("signed tx: {}", hex::encode(&signed_tx));

        let res = customer_sign_escrow_transaction(
            &txid,
            index,
            &cust_input_sk,
            bad_input_sats,
            output_sats,
            &cust_pk,
            &merch_pk,
            Some(&change_pk),
            change_pk_is_hash,
            tx_fee,
        );
        assert!(res.is_err());
    }

    #[test]
    fn form_dual_escrow_transaction() {
        // create customer utxo input
        let cust_input = UtxoInput {
            address_format: String::from("p2sh_p2wpkh"),
            transaction_id: hex::decode(
                "d21502c0d197e86b2847ff4c275ae989e06a52f09d60425701c2908217444326",
            )
            .unwrap(),
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(50 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let cust_private_key = BitcoinPrivateKey::<Testnet>::from_str(
            "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn",
        )
        .unwrap();
        let cust_input_sk =
            hex::decode("4157697b6428532758a9d0f9a73ce58befe3fd665797427d1c5bb3d33f6a132e")
                .unwrap();
        let cust_input_pk = cust_private_key
            .to_public_key()
            .to_secp256k1_public_key()
            .serialize_compressed()
            .to_vec();
        assert_eq!(
            cust_input_pk,
            hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb")
                .unwrap()
        );

        let cust_utxo = txutil::create_transaction_input(&cust_input, &cust_input_pk).unwrap();

        // create merchant utxo input
        let merch_input = UtxoInput {
            address_format: String::from("p2sh_p2wpkh"),
            transaction_id: hex::decode(
                "56fdf11a351768fdad77f633a8cc5a97ae361092174cb40da594dd9be2e69261",
            )
            .unwrap(),
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(50 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let merch_private_key = BitcoinPrivateKey::<Testnet>::from_str(
            "cNTSD7W8URSCmfPTvNf2B5gyKe2wwyNomkCikVhuHPCsFgBUKrAV",
        )
        .unwrap();
        let merch_input_sk =
            hex::decode("1a1971e1379beec67178509e25b6772c66cb67bb04d70df2b4bcdb8c08a00827")
                .unwrap();
        let merch_input_pk = merch_private_key
            .to_public_key()
            .to_secp256k1_public_key()
            .serialize_compressed()
            .to_vec();
        assert_eq!(
            merch_input_pk,
            hex::decode("03af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb353")
                .unwrap()
        );

        let merch_utxo = txutil::create_transaction_input(&merch_input, &merch_input_pk).unwrap();

        let cust_funding_sats = 2 * SATOSHI;
        let merch_funding_sats = 2 * SATOSHI;
        let cust_pk =
            hex::decode("0250a33b5a379c2143c7deb27345a4f16d6f766fbf31c4a477e64050b5ec506f03")
                .unwrap();
        let merch_pk =
            hex::decode("021df2e472ce4f5f76100a45f04f75bf8742a796a07a6abfc8ed2b9939588b981a")
                .unwrap();
        let cust_change_pk = Some((
            hex::decode("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")
                .unwrap(),
            false,
        ));
        let merch_change_pk = Some((
            hex::decode("02bf610ccd27d24b9718abb272fef97d3d342f083b3c6d495c05d98c0dd875fe41")
                .unwrap(),
            false,
        ));

        // now we can sign/form a transaction
        let escrow_tx = customer_sign_dual_escrow_transaction(
            &cust_utxo,
            &merch_utxo,
            cust_funding_sats,
            merch_funding_sats,
            &cust_pk,
            &merch_pk,
            cust_change_pk.clone(),
            merch_change_pk.clone(),
            Some((cust_input_sk, BitcoinFormat::P2SH_P2WPKH)),
        )
        .unwrap();

        // assert_eq!(escrow_tx.txid_be, escrow_tx2.txid_be);
        // assert_eq!(escrow_tx.prevout, escrow_tx2.prevout);
        println!("<==== Customer's perspective ====> ");
        println!("txid BE: {}", hex::encode(&escrow_tx.txid_be));
        println!("txid LE: {}", hex::encode(&escrow_tx.txid_le));
        println!("txid prevout: {}", hex::encode(&escrow_tx.prevout));

        println!(
            "Encoded Signature: {}",
            hex::encode(&escrow_tx.cust_signature)
        );
        println!("Encoded Pubkey: {}", hex::encode(&escrow_tx.cust_pubkey));

        // now have the merchant sign the transaction completely
        let (signed_tx, txid_be, txid_le, prevout) = merchant_sign_dual_escrow_transaction(
            &cust_utxo,
            &merch_utxo,
            &escrow_tx.cust_signature,
            &escrow_tx.cust_pubkey,
            cust_funding_sats,
            merch_funding_sats,
            &cust_pk,
            &merch_pk,
            cust_change_pk,
            merch_change_pk,
            &merch_input_sk,
        )
        .unwrap();

        println!("<==== Merchant's perspective ====> ");
        println!("Signed tx: {}", hex::encode(signed_tx));
        println!("txid_be: {}", hex::encode(txid_be));
        println!("txid_le: {}", hex::encode(txid_le));
        println!("prevout: {}", hex::encode(prevout));
    }

    #[test]
    fn form_mutual_close_transaction() {
        let escrow_input = UtxoInput {
            address_format: String::from("p2wsh"),
            // outpoint + txid
            transaction_id: hex::decode(
                "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1",
            )
            .unwrap(),
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(10 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let cust_escrow_sk =
            hex::decode("4157697b6428532758a9d0f9a73ce58befe3fd665797427d1c5bb3d33f6a132e")
                .unwrap();
        let merch_escrow_sk =
            hex::decode("1a1971e1379beec67178509e25b6772c66cb67bb04d70df2b4bcdb8c08a00827")
                .unwrap();

        let cust_pk =
            hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb")
                .unwrap();
        let cust_close_pk =
            hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb")
                .unwrap();
        let merch_pk =
            hex::decode("03af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb353")
                .unwrap();
        let merch_close_pk =
            hex::decode("02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af")
                .unwrap();

        let final_cust_bal = 8 * SATOSHI;
        let final_merch_bal = 2 * SATOSHI;

        let res_cust_signature = customer_sign_mutual_close_transaction(
            &escrow_input,
            &cust_pk,
            &merch_pk,
            &cust_close_pk,
            &merch_close_pk,
            final_cust_bal,
            final_merch_bal,
            &cust_escrow_sk,
        );
        assert!(res_cust_signature.is_ok());
        let cust_signature = res_cust_signature.unwrap();
        println!("cust sig: {}", hex::encode(&cust_signature));

        // now get merchant to sign as well
        let res = merchant_sign_mutual_close_transaction(
            &escrow_input,
            &cust_pk,
            &merch_pk,
            &cust_close_pk,
            &merch_close_pk,
            final_cust_bal,
            final_merch_bal,
            &cust_signature,
            &merch_escrow_sk,
        );
        assert!(res.is_ok());
        let (signed_mutual_tx, txid_be) = res.unwrap();

        println!("mutual close tx: {}", hex::encode(&signed_mutual_tx));
        println!("txid: {}", hex::encode(&txid_be));
    }

    #[test]
    fn claim_child_transaction_outputs() {
        let txid = hex::decode("d21502c0d197e86b2847ff4c275ae989e06a52f09d60425701c2908217444326")
            .unwrap();
        let index = 3;

        // customer's keypair for utxo
        let (_, cust_input_sk) = get_helper_utxo();

        let good_input_sats = 3 * SATOSHI;
        let tx_fee = 1000;
        let output_sats = good_input_sats - tx_fee;

        let output_pk =
            hex::decode("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")
                .unwrap();

        let (signed_tx, txid_buf) = create_child_transaction(
            txid,
            index,
            good_input_sats,
            output_sats,
            &output_pk,
            &cust_input_sk,
        ).unwrap();

        println!("signed tx: {}", hex::encode(&signed_tx));
        println!("txid: {}", hex::encode(&txid_buf));
        assert_eq!(hex::encode(&txid_buf), "6641ad3b397bfafbf7c2da144e0be04b71d2910afc9a8efebccdfb01ff3916c6");
    }
}
