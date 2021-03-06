use super::*;
use bitcoin::address::BitcoinAddress;
use bitcoin::network::BitcoinNetwork;
use bitcoin::SignatureHash::SIGHASH_ALL;
use bitcoin::{
    BitcoinAmount, BitcoinFormat, BitcoinPrivateKey, BitcoinTransaction, BitcoinTransactionInput,
    BitcoinTransactionOutput, BitcoinTransactionParameters,
};
use fixed_size_array::FixedSizeArray32;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use wagyu_model::crypto::hash160;
use wagyu_model::PrivateKey;
use wagyu_model::Transaction;

pub const SATOSHI: i64 = 100000000;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UtxoInput {
    pub address_format: String,
    pub transaction_id: Vec<u8>,
    pub index: u32,
    pub redeem_script: Option<Vec<u8>>,
    pub script_pub_key: Option<String>,
    pub utxo_amount: Option<i64>,
    pub sequence: Option<[u8; 4]>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Output {
    pub pubkey: Vec<u8>,
    pub amount: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChangeOutput {
    pub pubkey: Vec<u8>,
    pub amount: i64,
    pub is_hash: bool,
}

pub struct MultiSigOutput {
    pub cust_pubkey: Vec<u8>,
    pub merch_pubkey: Vec<u8>,
    pub address_format: &'static str,
    pub amount: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClosePublicKeys {
    pub cust_pk: Vec<u8>,
    pub cust_close_pk: Vec<u8>,
    pub merch_pk: Vec<u8>,
    pub merch_close_pk: Vec<u8>,
    pub merch_child_pk: Vec<u8>,
    pub merch_disp_pk: Vec<u8>,
    pub rev_lock: FixedSizeArray32,
}

/* Bitcoin transactions */
pub mod btc {
    use super::*;

    pub fn serialize_p2wsh_escrow_redeem_script(
        cust_pubkey: &Vec<u8>,
        merch_pubkey: &Vec<u8>,
    ) -> Vec<u8> {
        let mut script: Vec<u8> = Vec::new();
        script.extend(vec![0x52, 0x21]); // OP_2 + OP_DATA (pk1 len)
        script.extend(merch_pubkey.iter());
        script.push(0x21); // OP_DATA (pk2 len)
        script.extend(cust_pubkey.iter());
        script.extend(vec![0x52, 0xae]); // OP_2 OP_CHECKMULTISIG

        return script;
    }

    pub fn encode_self_delay(self_delay_le: &Vec<u8>) -> Result<Vec<u8>, String> {
        let self_delay: [u8; 2] = [self_delay_le[0] as u8, self_delay_le[1] as u8];
        let num = u16::from_le_bytes(self_delay);
        if num == 0 || num > 32767 {
            return Err(format!("self delay should be between [1, 32767]"));
        }

        if num <= 16 {
            // encode OP_1 to OP_16 without a length byte
            return Ok(vec![0x50 + num as u8]);
        } else if num < 128 {
            // encode 0x01 for lenth and self delay bytes
            return Ok(vec![0x01, num as u8]);
        }
        // encode 0x02 for length and self delay bytes
        let mut self_delay_buf = vec![0x02];
        self_delay_buf.extend(self_delay_le.iter());
        return Ok(self_delay_buf);
    }

    pub fn serialize_p2wsh_merch_close_redeem_script(
        cust_pubkey: &Vec<u8>,
        merch_pubkey: &Vec<u8>,
        merch_close_pubkey: &Vec<u8>,
        self_delay_le: &Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        //# P2WSH merch-close scriptPubKey
        //# 0x63      OP_IF
        //# 0x52      OP_2
        //# 0x21      OP_DATA - len(merch_pubkey)
        //# merch_pubkey
        //# 0x21      OP_DATA - len(cust_pubkey)
        //# cust_pubkey
        //# 0x52      OP_2
        //# 0xae      OP_CHECKMULTISIG
        //# 0x67      OP_ELSE
        //# 0x__      OP_DATA - len(to_self_delay) (probably ~0x02)
        //# to_self_delay
        //# 0xb2      OP_CHECKSEQUENCEVERIFY
        //# 0x75      OP_DROP
        //# 0x21      OP_DATA - len(merch_close_pubkey)
        //# merch_close_pk
        //# 0xac      OP_CHECKSIG
        //# 0x68      OP_ENDIF
        let self_delay_bytes = encode_self_delay(self_delay_le)?;

        let mut script: Vec<u8> = Vec::new();
        script.extend(vec![0x63, 0x52, 0x21]); // OP_IF + OP_2 + OP_DATA (pk1 len)
        script.extend(merch_pubkey.iter());
        script.push(0x21); // OP_DATA (pk2 len)
        script.extend(cust_pubkey.iter());
        script.extend(vec![0x52, 0xae, 0x67]); // OP_2 OP_CHECKMULTISIG
        script.extend(self_delay_bytes.iter()); // short sequence
        script.extend(vec![0xb2, 0x75, 0x21]);
        script.extend(merch_close_pubkey.iter());
        script.extend(vec![0xac, 0x68]);

        return Ok(script);
    }

    // given two public keys, create a multi-sig address via P2WSH script
    pub fn create_p2wsh_scriptpubkey<N: BitcoinNetwork>(
        cust_pubkey: &Vec<u8>,
        merch_pubkey: &Vec<u8>,
    ) -> Vec<u8> {
        // manually construct the script
        let mut script: Vec<u8> = Vec::new();
        script.extend(vec![0x52, 0x21]); // OP_2 + OP_DATA (pk1 len)
        script.extend(merch_pubkey.iter());
        script.push(0x21); // OP_DATA (pk2 len)
        script.extend(cust_pubkey.iter());
        script.extend(vec![0x52, 0xae]); // OP_2 OP_CHECKMULTISIG

        // compute SHA256 hash of script
        let script_hash = Sha256::digest(&script);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&script_hash);
        let mut script_pubkey = Vec::new();
        script_pubkey.extend(vec![0x00, 0x20]); // len of hash
        script_pubkey.extend_from_slice(&hash);

        return script_pubkey;
    }

    pub fn create_p2wpkh_scriptpubkey<N: BitcoinNetwork>(
        pubkey: &Vec<u8>,
        is_hash: bool,
    ) -> Vec<u8> {
        let mut script_pubkey = Vec::new();
        let script_hash = match is_hash {
            true => pubkey.clone(),
            false => {
                script_pubkey.extend(vec![0x00, 0x14]); // len of hash
                hash160(pubkey.as_slice())
            }
        };
        script_pubkey.extend_from_slice(&script_hash);

        return script_pubkey;
    }

    pub fn get_private_key<N: BitcoinNetwork>(
        private_key: &Vec<u8>,
    ) -> Result<BitcoinPrivateKey<N>, String> {
        let sk = match secp256k1::SecretKey::parse_slice(private_key) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string()),
        };
        let private_key = BitcoinPrivateKey::<N>::from_secp256k1_secret_key(&sk, false);
        Ok(private_key)
    }

    pub fn get_merch_close_timelocked_p2wsh_address(
        cust_pubkey: &Vec<u8>,
        merch_pubkey: &Vec<u8>,
        merch_close_pubkey: &Vec<u8>,
        self_delay_le: &Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        // get the script
        let script = serialize_p2wsh_merch_close_redeem_script(
            cust_pubkey,
            merch_pubkey,
            merch_close_pubkey,
            self_delay_le,
        )?;
        // compute SHA256 hash of script
        let script_hash = Sha256::digest(&script);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&script_hash);
        let mut script_pubkey = Vec::new();
        script_pubkey.extend(vec![0x00, 0x20]); // len of hash
        script_pubkey.extend_from_slice(&script_hash);

        return Ok(script_pubkey);
    }

    pub fn serialize_p2wsh_cust_close_redeem_script(
        rev_lock: &Vec<u8>,
        merch_disp_pubkey: &Vec<u8>,
        cust_close_pubkey: &Vec<u8>,
        self_delay_le: &Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        // P2WSH cust-close script
        //# 0x63      OP_IF
        //# 0xa8      OP_SHA256
        //# 0x20      OP_DATA - len(revocation_lock {sha256[revocation-secret]})
        //# revocation_lock
        //# 0x88      OP_EQUALVERIFY
        //# 0x21      OP_DATA - len(merch_disp_pubkey)
        //# merch_disp_pubkey
        //# 0x67      OP_ELSE
        //# 0x__      OP_DATA - len(to_self_delay) (probably ~0x02)
        //# to_self_delay
        //# 0xb2      OP_CHECKSEQUENCEVERIFY
        //# 0x75      OP_DROP
        //# 0x21      OP_DATA - len(cust_close_pubkey)
        //# cust_close_pk
        //# 0x68      OP_ENDIF
        //# 0xac      OP_CHECKSIG
        let self_delay_bytes = encode_self_delay(self_delay_le)?;

        let mut script: Vec<u8> = Vec::new();
        script.extend(vec![0x63, 0xa8, 0x20]);
        script.extend(rev_lock.iter());
        script.extend(vec![0x88, 0x21]);
        script.extend(merch_disp_pubkey.iter());
        script.push(0x67);
        script.extend(self_delay_bytes.iter()); // short sequence
        script.extend(vec![0xb2, 0x75, 0x21]);
        script.extend(cust_close_pubkey.iter());
        script.extend(vec![0x68, 0xac]);

        return Ok(script);
    }

    pub fn get_cust_close_timelocked_p2wsh_address(
        rev_lock: &[u8; 32],
        merch_disp_pubkey: &Vec<u8>,
        cust_close_pubkey: &Vec<u8>,
        self_delay_le: &Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        // println!("get_cust_close_timelocked_p2wsh_address script: {}", hex::encode(&script));
        let script = serialize_p2wsh_cust_close_redeem_script(
            &rev_lock.to_vec(),
            merch_disp_pubkey,
            cust_close_pubkey,
            self_delay_le,
        )?;
        // compute SHA256 hash of script
        let script_hash = Sha256::digest(&script);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&script_hash);
        let mut script_pubkey = Vec::new();
        script_pubkey.extend(vec![0x00, 0x20]); // len of hash
        script_pubkey.extend_from_slice(&script_hash);

        return Ok(script_pubkey);
    }

    pub fn create_opreturn_output(rev_lock: &[u8; 32], cust_close_pubkey: &Vec<u8>) -> Vec<u8> {
        let mut ret_val: Vec<u8> = Vec::new();
        let len = (rev_lock.len() + cust_close_pubkey.len()) as u8;
        ret_val.extend(vec![0x6a, len as u8]); // # OP_RETURN + OP_DATA
        ret_val.extend(rev_lock.iter()); // 32 bytes
        ret_val.extend(cust_close_pubkey.iter()); // 33 bytes
        return ret_val;
    }

    pub fn create_reverse_input(txid_be: &[u8; 32], index: u32, input_amount: i64) -> UtxoInput {
        let mut txid_buf_le = txid_be.clone();
        txid_buf_le.reverse();
        // let txid_str = hex::encode(&txid_buf);
        // println!("txid: {}", txid_str);
        UtxoInput {
            address_format: String::from("p2wsh"),
            // outpoint
            transaction_id: txid_buf_le.to_vec(),
            index: index,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(input_amount),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        }
    }

    pub fn create_utxo_input(txid_le: &[u8; 32], index: u32, input_amount: i64) -> UtxoInput {
        UtxoInput {
            address_format: String::from("p2wsh"),
            transaction_id: txid_le.to_vec(),
            index: index,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(input_amount),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        }
    }

    macro_rules! check_pk_valid {
        ($x: expr) => {
            match secp256k1::PublicKey::parse_slice(&$x, None) {
                Ok(_p) => true,
                Err(e) => return Err(e.to_string()),
            }
        };
    }

    // creates a funding transaction with the following input/outputs
    // input => p2pkh or p2sh_p2wpkh
    // output1 => multi-sig addr via p2wsh
    // output2 => change output to p2wpkh
    pub fn create_escrow_transaction<N: BitcoinNetwork>(
        input: &UtxoInput,
        index: usize,
        output1: &MultiSigOutput,
        output2: &ChangeOutput,
        private_key: BitcoinPrivateKey<N>,
    ) -> Result<(Vec<u8>, BitcoinTransaction<N>), String> {
        // check that specified public keys are valid
        check_pk_valid!(output1.cust_pubkey);
        check_pk_valid!(output1.merch_pubkey);
        if !output2.is_hash {
            check_pk_valid!(output2.pubkey);
        }
        let version = 2;
        let lock_time = 0;

        // types of UTXO inputs to support
        let address_format = match input.address_format.as_str() {
            "p2pkh" => BitcoinFormat::P2PKH,
            "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
            "p2wsh" => BitcoinFormat::P2WSH,
            _ => panic!(
                "do not currently support specified address format as funding input: {}",
                input.address_format
            ),
        };
        let address = private_key.to_address(&address_format).unwrap();
        let redeem_script = match (input.redeem_script.as_ref(), address_format.clone()) {
            (Some(script), _) => Some(script.clone()),
            (None, BitcoinFormat::P2SH_P2WPKH) => {
                let mut redeem_script = vec![0x00, 0x14];
                redeem_script.extend(&hash160(
                    &private_key
                        .to_public_key()
                        .to_secp256k1_public_key()
                        .serialize_compressed(),
                ));
                // println!("redeem_script: {}", hex::encode(&redeem_script));
                Some(redeem_script)
            }
            (None, _) => None,
        };
        let script_pub_key = input
            .script_pub_key
            .as_ref()
            .map(|script| hex::decode(script).unwrap());
        let sequence = input.sequence.map(|seq| seq.to_vec());

        let transaction_input = BitcoinTransactionInput::<N>::new(
            input.transaction_id.clone(),
            input.index,
            Some(address),
            Some(BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap()),
            redeem_script,
            script_pub_key,
            sequence,
            SIGHASH_ALL,
        )
        .unwrap();

        let mut input_vec = vec![];
        input_vec.push(transaction_input);

        let mut output_vec = vec![];

        // add multi-sig output as P2WSH output
        let output1_script_pubkey =
            create_p2wsh_scriptpubkey::<N>(&output1.cust_pubkey, &output1.merch_pubkey);
        // println!(
        //     "multi-sig script pubkey: {}",
        //     hex::encode(&output1_script_pubkey)
        // );
        let multisig_output = BitcoinTransactionOutput {
            amount: BitcoinAmount(output1.amount),
            script_pub_key: output1_script_pubkey,
        };
        // let out1 = multisig_output.serialize().unwrap();
        // println!("multisig_output script pubkey: {}", hex::encode(out1));

        // add P2WPKH output
        let output2_script_pubkey =
            create_p2wpkh_scriptpubkey::<N>(&output2.pubkey, output2.is_hash);
        let change_output = BitcoinTransactionOutput {
            amount: BitcoinAmount(output2.amount),
            script_pub_key: output2_script_pubkey,
        };
        //let out2 = change_output.serialize().unwrap();
        //println!("output2 script pubkey: {}", hex::encode(out2));

        output_vec.push(multisig_output);
        output_vec.push(change_output);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time: lock_time,
            segwit_flag: true,
        };

        let transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
        let hash_preimage = transaction
            .segwit_hash_preimage(index, SIGHASH_ALL)
            .unwrap();
        // return hash preimage of transaction and the transaction itself (for later signing)
        Ok((hash_preimage, transaction))
    }

    // form transaction input from UTXO
    pub fn form_transaction_input<N: BitcoinNetwork>(
        input: &UtxoInput,
        address: &BitcoinAddress<N>,
        input_pk: &Vec<u8>,
    ) -> Result<BitcoinTransactionInput<N>, String> {
        // types of UTXO inputs to support
        let address_format = match input.address_format.as_str() {
            "p2pkh" => BitcoinFormat::P2PKH,
            "p2wpkh" => BitcoinFormat::Bech32,
            "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
            "p2wsh" => BitcoinFormat::P2WSH,
            _ => {
                return Err(format!(
                    "do not currently support specified address format as funding input: {}",
                    input.address_format
                ))
            }
        };
        let redeem_script = match (input.redeem_script.as_ref(), address_format.clone()) {
            (Some(script), _) => Some(script.clone()),
            (None, BitcoinFormat::P2SH_P2WPKH) => {
                let mut redeem_script = vec![0x00, 0x14];
                redeem_script.extend(&hash160(input_pk));
                // println!("redeem_script: {}", hex::encode(&redeem_script));
                Some(redeem_script)
            }
            (None, _) => None,
        };
        let script_pub_key = input
            .script_pub_key
            .as_ref()
            .map(|script| hex::decode(script).unwrap());

        let sequence = input.sequence.map(|seq| seq.to_vec());

        let transaction_input = BitcoinTransactionInput::<N>::new(
            input.transaction_id.clone(),
            input.index,
            Some(address.clone()),
            Some(BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap()),
            redeem_script,
            script_pub_key,
            sequence,
            SIGHASH_ALL,
        )
        .unwrap();

        Ok(transaction_input)
    }

    pub fn form_single_escrow_transaction<N: BitcoinNetwork>(
        inputs: &Vec<BitcoinTransactionInput<N>>,
        index: usize,
        output1: &MultiSigOutput,
        output2: &ChangeOutput,
    ) -> Result<(Vec<u8>, BitcoinTransaction<N>), String> {
        // check that specified public keys are valid
        check_pk_valid!(output1.cust_pubkey);
        check_pk_valid!(output1.merch_pubkey);
        if !output2.is_hash {
            check_pk_valid!(output2.pubkey);
        }
        let version = 2;
        let lock_time = 0;

        let mut output_vec = vec![];

        // add multi-sig output as P2WSH output
        let output1_script_pubkey =
            create_p2wsh_scriptpubkey::<N>(&output1.cust_pubkey, &output1.merch_pubkey);
        // println!(
        //     "multi-sig script pubkey: {}",
        //     hex::encode(&output1_script_pubkey)
        // );
        let multisig_output = BitcoinTransactionOutput {
            amount: BitcoinAmount(output1.amount),
            script_pub_key: output1_script_pubkey,
        };
        // let out1 = multisig_output.serialize().unwrap();
        // println!("multisig_output script pubkey: {}", hex::encode(out1));

        // add P2WPKH output
        let output2_script_pubkey =
            create_p2wpkh_scriptpubkey::<N>(&output2.pubkey, output2.is_hash);
        let change_output = BitcoinTransactionOutput {
            amount: BitcoinAmount(output2.amount),
            script_pub_key: output2_script_pubkey,
        };
        //let out2 = change_output.serialize().unwrap();
        //println!("output2 script pubkey: {}", hex::encode(out2));

        output_vec.push(multisig_output);
        output_vec.push(change_output);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: inputs.clone(),
            outputs: output_vec,
            lock_time: lock_time,
            segwit_flag: true,
        };

        let transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
        let hash_preimage = transaction
            .segwit_hash_preimage(index, SIGHASH_ALL)
            .unwrap();
        // return hash preimage of transaction and the transaction itself (for later signing)
        Ok((hash_preimage, transaction))
    }

    pub fn compute_transaction_id_without_witness<N: BitcoinNetwork>(
        unsigned_tx: BitcoinTransaction<N>,
        private_key: BitcoinPrivateKey<N>,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
        // TODO: figure out why signing is required to get the correct transaction id
        let signed_tx = unsigned_tx.sign(&private_key).unwrap();
        // assume little endian here
        let tx_id_hex = signed_tx.to_transaction_id().unwrap();
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

        Ok((txid_buf_be, txid_buf_le, hash_prevout))
    }

    // creates a funding transaction with the following input/outputs
    // input1 & input2 => p2pkh or p2sh_p2wpkh
    // output0 => multi-sig addr via p2wsh
    // output1 => change output to p2wpkh (customer)
    // output1 => change output to p2wpkh (merchant)
    pub fn form_dual_escrow_transaction<N: BitcoinNetwork>(
        inputs: &Vec<BitcoinTransactionInput<N>>,
        index: usize,
        output0: &MultiSigOutput,
        change_outputs: &Vec<ChangeOutput>,
    ) -> Result<(Vec<u8>, BitcoinTransaction<N>), String> {
        // check that specified public keys are valid
        check_pk_valid!(output0.cust_pubkey);
        check_pk_valid!(output0.merch_pubkey);

        let version = 2;
        let lock_time = 0;

        let mut output_vec = vec![];

        // add multi-sig output as P2WSH output
        let output0_script_pubkey =
            create_p2wsh_scriptpubkey::<N>(&output0.cust_pubkey, &output0.merch_pubkey);
        // println!(
        //     "multi-sig script pubkey: {}",
        //     hex::encode(&output0_script_pubkey)
        // );
        let multisig_output = BitcoinTransactionOutput {
            amount: BitcoinAmount(output0.amount),
            script_pub_key: output0_script_pubkey,
        };
        // let out0 = multisig_output.serialize().unwrap();
        // println!("multisig_output script pubkey: {}", hex::encode(out0));
        output_vec.push(multisig_output);

        // OPTIONAL: add P2WPKH change output
        for output in change_outputs {
            let output1_script_pubkey =
                create_p2wpkh_scriptpubkey::<N>(&output.pubkey, output.is_hash);
            let change_output = BitcoinTransactionOutput {
                amount: BitcoinAmount(output.amount),
                script_pub_key: output1_script_pubkey,
            };

            // debug
            // let out1 = change_output.serialize().unwrap();
            // println!("change output script pubkey: {}", hex::encode(out1));

            output_vec.push(change_output);
        }

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: inputs.clone(),
            outputs: output_vec,
            lock_time: lock_time,
            segwit_flag: true,
        };

        let transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
        let hash_preimage = transaction
            .segwit_hash_preimage(index, SIGHASH_ALL)
            .unwrap();
        // return hash preimage of transaction and the transaction itself (for later signing)
        Ok((hash_preimage, transaction))
    }

    pub fn cust_sign_dual_escrow_transaction<N: BitcoinNetwork>(
        inputs: &Vec<BitcoinTransactionInput<N>>,
        vin: usize,
        output0: &MultiSigOutput,
        change_outputs: &Vec<ChangeOutput>,
        private_key: &BitcoinPrivateKey<N>,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        // form the dual escrow transaction first
        let (tx_preimage, _) =
            form_dual_escrow_transaction(inputs, vin, output0, change_outputs).unwrap();

        // generate the signature on preimage and encode the public key
        let cust_signature =
            generate_signature_for_multi_sig_transaction::<N>(&tx_preimage, private_key).unwrap();

        // encode the public key
        let cust_public_key =
            encode_public_key_for_transaction::<N>(BitcoinFormat::P2SH_P2WPKH, private_key);

        Ok((cust_signature, cust_public_key))
    }

    // signs a given transaction using a specified private key
    // assumes that transaction has already been loaded
    pub fn sign_escrow_transaction<N: BitcoinNetwork>(
        unsigned_tx: BitcoinTransaction<N>,
        private_key: BitcoinPrivateKey<N>,
    ) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let signed_tx = unsigned_tx.sign(&private_key).unwrap();
        // assume little endian here
        let tx_id_hex = signed_tx.to_transaction_id().unwrap();

        let signed_tx_hex = signed_tx.to_transaction_bytes().unwrap();
        let txid = hex::decode(tx_id_hex.to_string()).unwrap();

        let mut txid_buf = [0u8; 32];
        let mut hash_prevout = [0u8; 32];
        txid_buf.copy_from_slice(txid.as_slice());
        let mut txid_buf_be = txid_buf.clone();
        txid_buf_be.reverse();

        let mut prevout_preimage: Vec<u8> = Vec::new();
        prevout_preimage.extend(txid_buf_be.iter()); // txid (big endian)
        prevout_preimage.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result = Sha256::digest(&Sha256::digest(&prevout_preimage));
        hash_prevout.copy_from_slice(&result);

        return (signed_tx_hex, txid_buf_be, hash_prevout);
    }

    pub fn get_var_length_int(value: u64) -> Result<Vec<u8>, String> {
        match value {
            // bounded by u8::max_value()
            0..=252 => Ok(vec![value as u8]),
            // bounded by u16::max_value()
            253..=65535 => Ok([vec![0xfd], (value as u16).to_le_bytes().to_vec()].concat()),
            // bounded by u32::max_value()
            65536..=4294967295 => Ok([vec![0xfe], (value as u32).to_le_bytes().to_vec()].concat()),
            // bounded by u64::max_value()
            _ => Ok([vec![0xff], value.to_le_bytes().to_vec()].concat()),
        }
    }

    pub fn merch_generate_transaction_id<N: BitcoinNetwork>(
        tx_params: BitcoinTransactionParameters<N>,
    ) -> Result<([u8; 32], [u8; 32]), String> {
        let transaction = BitcoinTransaction::<N>::new(&tx_params).unwrap();
        let tx_id_hex = transaction.to_transaction_id().unwrap();
        let txid = hex::decode(tx_id_hex.to_string()).unwrap();

        let mut txid_buf = [0u8; 32];
        let mut hash_prevout = [0u8; 32];
        txid_buf.copy_from_slice(txid.as_slice());
        let mut txid_buf_be = txid_buf.clone();
        txid_buf_be.reverse();

        // get the txid and prevout
        let mut prevout_preimage: Vec<u8> = Vec::new();
        prevout_preimage.extend(txid_buf_be.iter()); // txid
        prevout_preimage.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result = Sha256::digest(&Sha256::digest(&prevout_preimage));
        hash_prevout.copy_from_slice(&result);

        Ok((txid_buf_be, hash_prevout))
    }

    pub fn encode_public_key_for_transaction<N: BitcoinNetwork>(
        address_format: BitcoinFormat,
        private_key: &BitcoinPrivateKey<N>,
    ) -> Vec<u8> {
        let public_key = private_key.to_public_key();
        let public_key_bytes = match (&address_format, public_key.is_compressed()) {
            (BitcoinFormat::P2PKH, false) => {
                public_key.to_secp256k1_public_key().serialize().to_vec()
            }
            _ => public_key
                .to_secp256k1_public_key()
                .serialize_compressed()
                .to_vec(),
        };
        let public_key = [vec![public_key_bytes.len() as u8], public_key_bytes].concat();
        return public_key;
    }

    pub fn completely_sign_multi_sig_transaction<N: BitcoinNetwork>(
        tx_params: &BitcoinTransactionParameters<N>,
        signature: &Vec<u8>,
        prepend_signature: bool,
        script_data: Option<Vec<u8>>,
        private_key: &BitcoinPrivateKey<N>,
    ) -> (BitcoinTransaction<N>, [u8; 32], [u8; 32]) {
        let mut tx_params2 = tx_params.clone();
        let checksig_bug = vec![0x00]; // OP_CHECKSIG bug
        tx_params2.inputs[0]
            .witnesses
            .append(&mut vec![checksig_bug]);
        tx_params2.inputs[0].additional_witness = Some((signature.clone(), prepend_signature));
        tx_params2.inputs[0].witness_script_data = script_data;
        let transaction = BitcoinTransaction::<N>::new(&tx_params2).unwrap();

        let signed_tx = transaction.sign(private_key).unwrap();
        // assume little endian here
        let tx_id_hex = signed_tx.to_transaction_id().unwrap();
        let txid = hex::decode(tx_id_hex.to_string()).unwrap();

        let mut txid_buf = [0u8; 32];
        let mut hash_prevout = [0u8; 32];
        txid_buf.copy_from_slice(txid.as_slice());
        let mut txid_buf_be = txid_buf.clone();
        txid_buf_be.reverse();

        // get the txid and prevout
        let mut prevout_preimage: Vec<u8> = Vec::new();
        prevout_preimage.extend(txid_buf_be.iter()); // txid
        prevout_preimage.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result = Sha256::digest(&Sha256::digest(&prevout_preimage));
        hash_prevout.copy_from_slice(&result);

        return (signed_tx, txid_buf_be, hash_prevout);
    }

    pub fn generate_signature_for_multi_sig_transaction<N: BitcoinNetwork>(
        preimage: &Vec<u8>,
        private_key: &BitcoinPrivateKey<N>,
    ) -> Result<Vec<u8>, String> {
        let transaction_hash = Sha256::digest(&Sha256::digest(preimage));
        let sighash_code = SIGHASH_ALL as u32;

        // Signature
        let (signature, _) = secp256k1::sign(
            &secp256k1::Message::parse_slice(&transaction_hash).unwrap(),
            &private_key.to_secp256k1_secret_key(),
        );
        let mut signature = signature.serialize_der().as_ref().to_vec();
        signature.push(sighash_code.to_le_bytes()[0]);
        let signature = [get_var_length_int(signature.len() as u64)?, signature].concat();
        Ok(signature)
    }

    pub fn sign_merch_close_transaction<N: BitcoinNetwork>(
        unsigned_tx: BitcoinTransaction<N>,
        private_key: String,
    ) -> String {
        let private_key = BitcoinPrivateKey::<N>::from_str(private_key.as_str()).unwrap();

        let signed_tx = unsigned_tx.sign(&private_key).unwrap();
        let signed_tx_hex = hex::encode(signed_tx.to_transaction_bytes().unwrap());

        return signed_tx_hex;
    }

    // creates a merch-close-tx that spends from a P2WSH to another
    pub fn create_merch_close_transaction_params<N: BitcoinNetwork>(
        input: &UtxoInput,
        fee_mc: i64,
        val_cpfp: i64,
        cust_pubkey: &Vec<u8>,
        merch_pubkey: &Vec<u8>,
        merch_close_pubkey: &Vec<u8>,
        merch_child_pubkey: &Vec<u8>,
        self_delay_be: &[u8; 2],
    ) -> Result<BitcoinTransactionParameters<N>, String> {
        let version = 2;
        let lock_time = 0;
        let mut self_delay_le = self_delay_be.to_vec();
        self_delay_le.reverse();
        let address_format = match input.address_format.as_str() {
            "p2pkh" => BitcoinFormat::P2PKH,
            "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
            "p2wsh" => BitcoinFormat::P2WSH,
            _ => {
                return Err(format!(
                    "do not currently support specified address format: {}",
                    input.address_format
                ))
            }
        };

        let redeem_script = match (input.redeem_script.as_ref(), address_format.clone()) {
            (Some(script), _) => Some(script.clone()),
            (None, BitcoinFormat::P2SH_P2WPKH) => {
                let redeem_script = serialize_p2wsh_escrow_redeem_script(cust_pubkey, merch_pubkey);
                // println!("redeem_script: {}", hex::encode(&redeem_script));
                Some(redeem_script)
            }
            (None, _) => None,
        };

        let address = match address_format {
            BitcoinFormat::P2WSH => {
                BitcoinAddress::<N>::p2wsh(redeem_script.as_ref().unwrap()).unwrap()
            }
            _ => {
                return Err(format!(
                    "address format {} not supported right now",
                    address_format
                ))
            }
        };
        // println!("address: {}", address);
        let sequence = input.sequence.map(|seq| seq.to_vec());
        // println!("redeem_script: {}", hex::encode(redeem_script.as_ref().unwrap()));

        let escrow_tx_input = BitcoinTransactionInput::<N>::new(
            input.transaction_id.clone(),
            input.index,
            Some(address),
            Some(BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap()),
            redeem_script,
            None,
            sequence,
            SIGHASH_ALL,
        )
        .unwrap();

        let mut input_vec = vec![];
        input_vec.push(escrow_tx_input);

        let musig_script_pubkey = get_merch_close_timelocked_p2wsh_address(
            cust_pubkey,
            merch_pubkey,
            merch_close_pubkey,
            &self_delay_le,
        )?;
        // output 1: multi signature output
        let musig_output = BitcoinTransactionOutput {
            amount: BitcoinAmount::from_satoshi(input.utxo_amount.unwrap() - val_cpfp - fee_mc)
                .unwrap(),
            script_pub_key: musig_script_pubkey,
        };
        // output 2: CPFP P2WPKH output to merch child
        let output2_script_pubkey = create_p2wpkh_scriptpubkey::<N>(&merch_child_pubkey, false);
        // println!("(2) to_merchant: {}", hex::encode(&output4_script_pubkey));
        let cpfp = BitcoinTransactionOutput {
            amount: BitcoinAmount::from_satoshi(val_cpfp).unwrap(),
            script_pub_key: output2_script_pubkey,
        };
        // println!("Multi-sig output script pubkey: {}", hex::encode(musig_output.serialize().unwrap()));

        let mut output_vec = vec![];
        output_vec.push(musig_output);
        output_vec.push(cpfp);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time: lock_time,
            segwit_flag: true,
        };

        Ok(transaction_parameters)
    }

    pub fn create_merch_close_transaction_preimage<N: BitcoinNetwork>(
        transaction_parameters: &BitcoinTransactionParameters<N>,
    ) -> Result<(Vec<u8>, BitcoinTransaction<N>), String> {
        let transaction = handle_error!(BitcoinTransaction::<N>::new(transaction_parameters));
        let hash_preimage = handle_error!(transaction.segwit_hash_preimage(0, SIGHASH_ALL));

        return Ok((hash_preimage, transaction));
    }

    pub fn merchant_form_close_transaction<N: BitcoinNetwork>(
        escrow_txid_be: Vec<u8>,
        cust_pk: Vec<u8>,
        merch_pk: Vec<u8>,
        merch_close_pk: Vec<u8>,
        merch_child_pk: Vec<u8>,
        cust_bal_sats: i64,
        merch_bal_sats: i64,
        fee_mc: i64,
        val_cpfp: i64,
        to_self_delay_be: [u8; 2],
    ) -> Result<(Vec<u8>, BitcoinTransactionParameters<N>), String> {
        // check_pk_length!(cust_pk);
        // check_pk_length!(merch_pk);
        // check_pk_length!(merch_close_pk);

        let redeem_script = serialize_p2wsh_escrow_redeem_script(&cust_pk, &merch_pk);
        let escrow_index = 0;
        let mut escrow_txid_le = escrow_txid_be.clone();
        escrow_txid_le.reverse();

        let input = UtxoInput {
            address_format: String::from("p2wsh"),
            // outpoint of escrow
            transaction_id: escrow_txid_le,
            index: escrow_index,
            redeem_script: Some(redeem_script),
            script_pub_key: None,
            utxo_amount: Some(cust_bal_sats + merch_bal_sats),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };
        let tx_params = create_merch_close_transaction_params::<N>(
            &input,
            fee_mc,
            val_cpfp,
            &cust_pk,
            &merch_pk,
            &merch_close_pk,
            &merch_child_pk,
            &to_self_delay_be,
        )?;

        let (merch_tx_preimage, _) = create_merch_close_transaction_preimage::<N>(&tx_params)?;

        Ok((merch_tx_preimage, tx_params))
    }

    pub fn create_cust_close_transaction<N: BitcoinNetwork>(
        input: &UtxoInput,
        pubkeys: &ClosePublicKeys,
        self_delay_be: &[u8; 2],
        cust_bal: i64,
        merch_bal: i64,
        fee_cc: i64,
        fee_mc: i64,
        val_cpfp: i64,
        from_escrow: bool,
    ) -> Result<
        (
            Vec<u8>,
            BitcoinTransactionParameters<N>,
            BitcoinTransaction<N>,
        ),
        String,
    > {
        let version = 2;
        let lock_time = 0;
        let mut self_delay_le = self_delay_be.to_vec();
        self_delay_le.reverse();
        let address_format = match input.address_format.as_str() {
            "p2wsh" => BitcoinFormat::P2WSH,
            _ => {
                return Err(format!(
                    "do not currently support specified address format: {}",
                    input.address_format
                ))
            }
        };

        let redeem_script = match from_escrow {
            true => {
                let redeem_script =
                    serialize_p2wsh_escrow_redeem_script(&pubkeys.cust_pk, &pubkeys.merch_pk);
                // println!("escrow-tx redeem_script: {}", hex::encode(&redeem_script));
                Some(redeem_script)
            }
            false => {
                let redeem_script = serialize_p2wsh_merch_close_redeem_script(
                    &pubkeys.cust_pk,
                    &pubkeys.merch_pk,
                    &pubkeys.merch_close_pk,
                    &self_delay_le,
                )?;
                // println!("merch-close-tx redeem_script: {}", hex::encode(&redeem_script));
                Some(redeem_script)
            }
        };
        let address = match address_format {
            BitcoinFormat::P2WSH => {
                BitcoinAddress::<N>::p2wsh(redeem_script.as_ref().unwrap()).unwrap()
            }
            _ => return Err(format!("do not currently support specified address format")),
        };
        // println!("address: {}", address);
        let sequence = input.sequence.map(|seq| seq.to_vec());

        let escrow_tx_input = BitcoinTransactionInput::<N>::new(
            input.transaction_id.clone(),
            input.index,
            Some(address),
            Some(BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap()),
            redeem_script,
            None,
            sequence,
            SIGHASH_ALL,
        )
        .unwrap();

        let mut input_vec = vec![];
        input_vec.push(escrow_tx_input);

        // output 1: P2WSH output to customer (handles spending from escrow-tx or merch-close-tx
        let output1_script_pubkey = get_cust_close_timelocked_p2wsh_address(
            &pubkeys.rev_lock.0,
            &pubkeys.merch_disp_pk,
            &pubkeys.cust_close_pk,
            &self_delay_le,
        )?;

        // println!("(1) to_customer: {}", hex::encode(&output1_script_pubkey));
        let to_cust_amount = cust_bal - fee_cc - val_cpfp;
        let to_customer = BitcoinTransactionOutput {
            amount: BitcoinAmount::from_satoshi(to_cust_amount).unwrap(),
            script_pub_key: output1_script_pubkey,
        };
        // println!("to_customer: {}", hex::encode(to_customer.serialize().unwrap()));

        // output 2: P2WPKH output to merchant
        let output2_script_pubkey = create_p2wpkh_scriptpubkey::<N>(&pubkeys.merch_close_pk, false);
        // println!("(2) to_merchant: {}", hex::encode(&output2_script_pubkey));
        let to_merch_amount = match from_escrow {
            true => merch_bal,
            false => merch_bal - fee_mc - val_cpfp,
        };
        let to_merchant = BitcoinTransactionOutput {
            amount: BitcoinAmount::from_satoshi(to_merch_amount).unwrap(),
            script_pub_key: output2_script_pubkey,
        };
        // println!("to_merchant: {}", hex::encode(to_merchant.serialize().unwrap()));

        // output 3: OP_RETURN output
        let output3_script_pubkey =
            create_opreturn_output(&pubkeys.rev_lock.0, &pubkeys.cust_close_pk);
        // println!("(3) OP_RETURN: {}", hex::encode(&output3_script_pubkey));
        let op_return_out = BitcoinTransactionOutput {
            amount: BitcoinAmount::from_satoshi(0).unwrap(),
            script_pub_key: output3_script_pubkey,
        };
        // println!("op_return: {}", hex::encode(op_return_out.serialize().unwrap()));

        // output 4: P2WPKH output to cust child
        let output4_script_pubkey = create_p2wpkh_scriptpubkey::<N>(&pubkeys.cust_close_pk, false);
        // println!("(2) to_merchant: {}", hex::encode(&output4_script_pubkey));
        let cpfp = BitcoinTransactionOutput {
            amount: BitcoinAmount::from_satoshi(val_cpfp).unwrap(),
            script_pub_key: output4_script_pubkey,
        };
        // println!("to_merchant: {}", hex::encode(cpfp.serialize().unwrap()));

        let mut output_vec = vec![];
        output_vec.push(to_customer);
        output_vec.push(to_merchant);
        output_vec.push(op_return_out);
        output_vec.push(cpfp);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time: lock_time,
            segwit_flag: true,
        };

        let transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
        let hash_preimage = transaction.segwit_hash_preimage(0, SIGHASH_ALL).unwrap();

        return Ok((hash_preimage, transaction_parameters, transaction));
    }

    pub fn create_mutual_close_transaction<N: BitcoinNetwork>(
        input: &UtxoInput,
        cust_pk: &Vec<u8>,
        merch_pk: &Vec<u8>,
        cust_close_pk: &Vec<u8>,
        merch_close_pk: &Vec<u8>,
        final_cust_bal: i64,
        final_merch_bal: i64,
    ) -> Result<
        (
            Vec<u8>,
            BitcoinTransactionParameters<N>,
            BitcoinTransaction<N>,
        ),
        String,
    > {
        let version = 2;
        let lock_time = 0;
        let address_format = match input.address_format.as_str() {
            "p2wsh" => BitcoinFormat::P2WSH,
            _ => {
                return Err(format!(
                    "do not currently support specified address format: {}",
                    input.address_format
                ))
            }
        };
        let escrow_amount = input.utxo_amount.unwrap();
        if escrow_amount < (final_cust_bal + final_merch_bal) {
            return Err(format!(
                "Escrow input amount is less than sum of output amounts"
            ));
        }

        let redeem_script = serialize_p2wsh_escrow_redeem_script(&cust_pk, &merch_pk);
        let address = match address_format {
            BitcoinFormat::P2WSH => BitcoinAddress::<N>::p2wsh(&redeem_script).unwrap(),
            _ => return Err(format!("do not currently support specified address format")),
        };
        // println!("address: {}", address);
        let sequence = input.sequence.map(|seq| seq.to_vec());

        let escrow_tx_input = BitcoinTransactionInput::<N>::new(
            input.transaction_id.clone(),
            input.index,
            Some(address),
            Some(BitcoinAmount::from_satoshi(escrow_amount).unwrap()),
            Some(redeem_script),
            None,
            sequence,
            SIGHASH_ALL,
        )
        .unwrap();

        let mut input_vec = vec![];
        input_vec.push(escrow_tx_input);

        // output 1: P2WPKH output to customer
        let output1_script_pubkey = create_p2wpkh_scriptpubkey::<N>(&cust_close_pk, false);
        // println!("(1) to_customer: {}", hex::encode(&output1_script_pubkey));
        let to_customer = BitcoinTransactionOutput {
            amount: BitcoinAmount::from_satoshi(final_cust_bal).unwrap(),
            script_pub_key: output1_script_pubkey,
        };

        // output 2: P2WPKH output to merchant
        let output2_script_pubkey = create_p2wpkh_scriptpubkey::<N>(&merch_close_pk, false);
        // println!("(2) to_merchant: {}", hex::encode(&output2_script_pubkey));
        let to_merchant = BitcoinTransactionOutput {
            amount: BitcoinAmount::from_satoshi(final_merch_bal).unwrap(),
            script_pub_key: output2_script_pubkey,
        };

        let mut output_vec = vec![];
        output_vec.push(to_customer);
        output_vec.push(to_merchant);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time: lock_time,
            segwit_flag: true,
        };

        let transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
        let hash_preimage = transaction.segwit_hash_preimage(0, SIGHASH_ALL).unwrap();

        return Ok((hash_preimage, transaction_parameters, transaction));
    }

    // transaction for customer to claim their output from cust-close-from-*-tx after timelock
    pub fn sign_cust_close_claim_transaction_helper<N: BitcoinNetwork>(
        txid_le: Vec<u8>,
        index: u32,
        input_sats: i64,
        private_key: BitcoinPrivateKey<N>,
        cpfp_input: Option<UtxoInput>,
        cpfp_private_key: Option<BitcoinPrivateKey<N>>,
        output: Output,
        self_delay_be: [u8; 2],
        rev_lock: Vec<u8>,
        merch_disp_pk: Vec<u8>,
        cust_close_pk: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let version = 2;
        let lock_time = 0;

        let mut self_delay_le = self_delay_be.to_vec();
        self_delay_le.reverse();
        let redeem_script = serialize_p2wsh_cust_close_redeem_script(
            &rev_lock,
            &merch_disp_pk,
            &cust_close_pk,
            &self_delay_le,
        )?;
        let address = BitcoinAddress::<N>::p2wsh(&redeem_script).unwrap();
        let mut sequence: Vec<u8> = vec![0x00, 0x00].to_vec();
        sequence.append(&mut self_delay_be.to_vec());
        sequence.reverse();

        let mut cust_close_tx_input = BitcoinTransactionInput::<N>::new(
            txid_le,
            index,
            Some(address),
            Some(BitcoinAmount::from_satoshi(input_sats).unwrap()),
            Some(redeem_script),
            None,
            Some(sequence),
            SIGHASH_ALL,
        )
        .unwrap();

        // "00" so we enter OP_ELSE in the script
        let script_data: Vec<u8> = vec![0x00];
        // false so that script_data should be appended after signature on stack
        cust_close_tx_input.additional_witness = Some((script_data, false));
        // cust_close_tx_input.witness_script_data = None;

        let mut input_vec = vec![];
        input_vec.push(cust_close_tx_input);
        if cpfp_input.is_some() {
            let input = cpfp_input.unwrap();
            let address = handle_error!(private_key.to_address(&BitcoinFormat::Bech32));
            let cpfp_tx_input = handle_error!(BitcoinTransactionInput::<N>::new(
                input.transaction_id.clone(),
                input.index,
                Some(address),
                Some(BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap()),
                None,
                None,
                Some(vec![0xff, 0xff, 0xff, 0xff]),
                SIGHASH_ALL,
            ));
            input_vec.push(cpfp_tx_input);
        }

        // add P2WPKH output
        let output_script_pk = create_p2wpkh_scriptpubkey::<N>(&output.pubkey, false);
        let p2wpkh_output = BitcoinTransactionOutput {
            amount: BitcoinAmount::from_satoshi(output.amount).unwrap(),
            script_pub_key: output_script_pk,
        };

        let mut output_vec = vec![];
        output_vec.push(p2wpkh_output);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time: lock_time,
            segwit_flag: true,
        };

        let transaction = handle_error!(BitcoinTransaction::<N>::new(&transaction_parameters));
        let signed_tx = match transaction.sign(&private_key) {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to sign transaction: {:?}", e)),
        };

        if cpfp_private_key.is_some() {
            let private_key1 = cpfp_private_key.unwrap();
            let full_signed_tx = handle_error!(signed_tx.sign(&private_key1));
            let signed_tx_vec = handle_error!(full_signed_tx.to_transaction_bytes());
            let txid_str = handle_error!(signed_tx.to_transaction_id());
            let txid_bytes = handle_error!(hex::decode(txid_str.to_string()));
            return Ok((signed_tx_vec, txid_bytes));
        }

        let signed_tx_vec = handle_error!(signed_tx.to_transaction_bytes());
        let txid_str = handle_error!(signed_tx.to_transaction_id());
        let txid_bytes = handle_error!(hex::decode(txid_str.to_string()));
        Ok((signed_tx_vec, txid_bytes))
    }

    // justice transaction for merchant to dispute the cust-close-from-tx via revoked rev-lock/rev-secret
    pub fn sign_merch_dispute_transaction_helper<N: BitcoinNetwork>(
        txid_le: Vec<u8>,
        index: u32,
        input_sats: i64,
        output: Output,
        self_delay_be: [u8; 2],
        rev_lock: Vec<u8>,
        rev_secret: Vec<u8>,
        cust_close_pk: Vec<u8>,
        merch_disp_pk: Vec<u8>,
        private_key: BitcoinPrivateKey<N>,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let version = 2;
        let lock_time = 0;
        let mut self_delay_le = self_delay_be.to_vec();
        self_delay_le.reverse(); // now it's in big endian format

        let redeem_script = serialize_p2wsh_cust_close_redeem_script(
            &rev_lock,
            &merch_disp_pk,
            &cust_close_pk,
            &self_delay_le,
        )?;
        let address = BitcoinAddress::<N>::p2wsh(&redeem_script).unwrap();
        let transaction_id = txid_le.clone();
        let sequence: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff].to_vec();

        let mut cust_close_tx_input = BitcoinTransactionInput::<N>::new(
            transaction_id,
            index,
            Some(address),
            Some(BitcoinAmount::from_satoshi(input_sats).unwrap()),
            Some(redeem_script),
            None,
            Some(sequence),
            SIGHASH_ALL,
        )
        .unwrap();

        // "01" as a script args that we enter OP_IF in the script
        let script_data: Vec<u8> = vec![0x01];
        // prepend the rev_secret with a len byte
        let enc_rev_secret = [get_var_length_int(rev_secret.len() as u64)?, rev_secret].concat();
        // false so that rev_secret witness should be appended after signature on stack
        cust_close_tx_input.additional_witness = Some((enc_rev_secret.clone(), false));
        cust_close_tx_input.witness_script_data = Some(script_data);

        let mut input_vec = vec![];
        input_vec.push(cust_close_tx_input);

        // add P2WPKH output
        let output_script_pk = create_p2wpkh_scriptpubkey::<N>(&output.pubkey, false);
        let p2wpkh_output = BitcoinTransactionOutput {
            amount: BitcoinAmount::from_satoshi(output.amount).unwrap(),
            script_pub_key: output_script_pk,
        };

        let mut output_vec = vec![];
        output_vec.push(p2wpkh_output);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time: lock_time,
            segwit_flag: true,
        };

        let transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
        let hash_preimage = transaction.segwit_hash_preimage(0, SIGHASH_ALL).unwrap();

        let signed_tx = match transaction.sign(&private_key) {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to sign transaction: {:?}", e)),
        };

        let signed_tx_vec = signed_tx.to_transaction_bytes().unwrap();
        Ok((signed_tx_vec, hash_preimage))
    }

    // merchant claiming the `to_merchant` output in the cust-close-*-tx (spendable immediately)
    pub fn sign_merch_claim_transaction_helper<N: BitcoinNetwork>(
        input: UtxoInput,
        output: Output,
        private_key: BitcoinPrivateKey<N>,
        cpfp_input: Option<UtxoInput>,
        cpfp_key: Option<BitcoinPrivateKey<N>>,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let version = 2;
        let lock_time = 0;
        let address_format = match input.address_format.as_str() {
            "p2wpkh" => BitcoinFormat::Bech32, // output of cust-close-*-tx or cpfp_output
            "p2wsh" => BitcoinFormat::P2WSH,   // output of merch-close-tx
            _ => {
                return Err(format!(
                    "do not currently support specified address format: {}",
                    input.address_format
                ))
            }
        };
        let redeem_script = match (input.redeem_script.as_ref(), address_format.clone()) {
            (Some(script), BitcoinFormat::P2WSH) => Some(script.clone()),
            (_, _) => None,
        };
        let script_pub_key = input
            .script_pub_key
            .map(|script| hex::decode(script).unwrap());
        let sequence = input.sequence.map(|seq| seq.to_vec());

        let address = match address_format {
            BitcoinFormat::P2WSH => {
                BitcoinAddress::<N>::p2wsh(redeem_script.as_ref().unwrap()).unwrap()
            }
            BitcoinFormat::Bech32 => private_key.to_address(&address_format).unwrap(),
            _ => {
                return Err(format!(
                    "address format {} not supported right now",
                    address_format
                ))
            }
        };

        let mut tx_input = BitcoinTransactionInput::<N>::new(
            input.transaction_id.clone(),
            input.index,
            Some(address),
            Some(BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap()),
            redeem_script,
            script_pub_key,
            sequence,
            SIGHASH_ALL,
        )
        .unwrap();

        if address_format == BitcoinFormat::P2WSH {
            // "00" so we enter OP_ELSE in the script
            let script_data: Vec<u8> = vec![0x00];
            // false so that script_data should be appended after signature on stack
            tx_input.additional_witness = Some((script_data, false));
        }

        let mut input_vec = vec![];
        input_vec.push(tx_input);

        // check for cpfp
        if cpfp_input.is_some() && cpfp_key.is_some() {
            let input1 = cpfp_input.unwrap();
            let private_key1 = cpfp_key.clone().unwrap();
            let address1 = handle_error!(private_key1.to_address(&BitcoinFormat::Bech32));
            let public_key1 = private_key1
                .to_public_key()
                .to_secp256k1_public_key()
                .serialize_compressed()
                .to_vec();
            let cpfp_tx_input = handle_error!(transactions::btc::form_transaction_input::<N>(
                &input1,
                &address1,
                &public_key1
            ));
            input_vec.push(cpfp_tx_input);
        }

        // add P2WPKH output
        let output_script_pubkey = create_p2wpkh_scriptpubkey::<N>(&output.pubkey, false);
        let p2wpkh_output = BitcoinTransactionOutput {
            amount: BitcoinAmount(output.amount),
            script_pub_key: output_script_pubkey,
        };

        let mut output_vec = vec![];
        output_vec.push(p2wpkh_output);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time: lock_time,
            segwit_flag: true,
        };

        let transaction = handle_error!(BitcoinTransaction::<N>::new(&transaction_parameters));
        let signed_tx = match transaction.sign(&private_key) {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to sign transaction: {:?}", e)),
        };

        if cpfp_key.is_some() {
            let private_key1 = cpfp_key.unwrap();
            let fully_signed_tx = handle_error!(transaction.sign(&private_key1));
            let signed_tx_vec = handle_error!(fully_signed_tx.to_transaction_bytes());
            let txid_str = handle_error!(signed_tx.to_transaction_id());
            let txid_bytes = handle_error!(hex::decode(txid_str.to_string()));
            return Ok((signed_tx_vec, txid_bytes));
        }
        let signed_tx_vec = handle_error!(signed_tx.to_transaction_bytes());
        let txid_str = handle_error!(signed_tx.to_transaction_id());
        let txid_bytes = handle_error!(hex::decode(txid_str.to_string()));
        Ok((signed_tx_vec, txid_bytes))
    }

    pub fn generate_customer_close_tx_helper<N: BitcoinNetwork>(
        close_escrow_signature: &Option<String>,
        escrow_tx_preimage: &Vec<u8>,
        escrow_tx_params: &BitcoinTransactionParameters<N>,
        close_merch_signature: &Option<String>,
        merch_tx_preimage: &Vec<u8>,
        merch_tx_params: &BitcoinTransactionParameters<N>,
        from_escrow: bool,
        merch_pk: &Vec<u8>,
        cust_sk: &Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let sighash_code = SIGHASH_ALL as u32;
        let private_key = match get_private_key::<N>(cust_sk) {
            Ok(p) => p,
            Err(e) => return Err(e.to_string()),
        };
        let pk_m = PublicKey::parse_slice(merch_pk, None).unwrap();

        match from_escrow {
            true => {
                let escrow_signature = match close_escrow_signature.clone() {
                    Some(n) => match hex::decode(n) {
                        Ok(s) => match secp256k1::Signature::parse_slice(&s) {
                            Ok(t) => t,
                            Err(e) => {
                                return Err(format!(
                                    "error parsing close_escrow_signature = {}",
                                    e.to_string()
                                ))
                            }
                        },
                        Err(e) => return Err(e.to_string()),
                    },
                    None => {
                        return Err(String::from(
                            "do not have a merchant signature on cust-close from escrow tx",
                        ))
                    }
                };
                let escrow_tx_hash = Sha256::digest(&Sha256::digest(&escrow_tx_preimage));
                let msg = secp256k1::Message::parse_slice(&escrow_tx_hash).unwrap();
                let escrow_sig_valid = verify(&msg, &escrow_signature, &pk_m);
                if escrow_sig_valid {
                    // customer sign the transactions to complete multi-sig and store CT bytes locally
                    let mut escrow_signature = escrow_signature.serialize_der().as_ref().to_vec();
                    escrow_signature.push(sighash_code.to_le_bytes()[0]);
                    let enc_escrow_signature = [
                        get_var_length_int(escrow_signature.len() as u64).unwrap(),
                        escrow_signature,
                    ]
                    .concat();

                    // sign the cust-close-from-escrow-tx
                    let (signed_cust_close_escrow_tx, close_escrow_txid_be, _) =
                        completely_sign_multi_sig_transaction::<N>(
                            &escrow_tx_params,
                            &enc_escrow_signature,
                            true,
                            None,
                            &private_key,
                        );
                    let mut close_escrow_txid_le = close_escrow_txid_be.to_vec();
                    close_escrow_txid_le.reverse();
                    let close_escrow_tx =
                        signed_cust_close_escrow_tx.to_transaction_bytes().unwrap();

                    Ok((
                        close_escrow_tx,
                        close_escrow_txid_be.to_vec(),
                        close_escrow_txid_le,
                    ))
                } else {
                    Err(String::from("<merch-sig> to spend from <escrow-tx> out of sync with current customer state"))
                }
            }
            false => {
                let merch_signature =
                    match close_merch_signature.clone() {
                        Some(n) => match hex::decode(n) {
                            Ok(s) => match secp256k1::Signature::parse_slice(&s) {
                                Ok(t) => t,
                                Err(e) => {
                                    return Err(format!(
                                        "error parsing close_merch_signature = {}",
                                        e.to_string()
                                    ))
                                }
                            },
                            Err(e) => return Err(e.to_string()),
                        },
                        None => return Err(String::from(
                            "do not have a merchant signature on cust-close from merch-close tx",
                        )),
                    };

                // sanity check on the signatures to make sure not out of sync with current state
                let merch_tx_hash = Sha256::digest(&Sha256::digest(&merch_tx_preimage));
                let msg = secp256k1::Message::parse_slice(&merch_tx_hash).unwrap();
                let merch_sig_valid = verify(&msg, &merch_signature, &pk_m);

                if merch_sig_valid {
                    // customer sign the transactions to complete multi-sig and store CT bytes locally
                    let mut merch_signature = merch_signature.serialize_der().as_ref().to_vec();
                    merch_signature.push(sighash_code.to_le_bytes()[0]);
                    let enc_merch_signature = [
                        get_var_length_int(merch_signature.len() as u64).unwrap(),
                        merch_signature,
                    ]
                    .concat();

                    // sign the cust-close-from-merch-tx
                    let script_data: Vec<u8> = vec![0x01];
                    let (signed_cust_close_merch_tx, close_merch_txid_be, _) =
                        completely_sign_multi_sig_transaction::<N>(
                            &merch_tx_params,
                            &enc_merch_signature,
                            true,
                            Some(script_data),
                            &private_key,
                        );
                    let mut close_merch_txid_le = close_merch_txid_be.to_vec();
                    close_merch_txid_le.reverse();
                    let close_merch_tx = signed_cust_close_merch_tx.to_transaction_bytes().unwrap();

                    Ok((
                        close_merch_tx,
                        close_merch_txid_be.to_vec(),
                        close_merch_txid_le,
                    ))
                } else {
                    Err(String::from("<merch-sig> to spend from <merch-close-tx> out of sync with current customer state"))
                }
            }
        }
    }

    pub fn sign_child_transaction_to_bump_fee_helper<N: BitcoinNetwork>(
        input1: UtxoInput,
        private_key1: &BitcoinPrivateKey<N>,
        input2: UtxoInput,
        private_key2: &BitcoinPrivateKey<N>,
        output: Output,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let version = 2;
        let lock_time = 0;

        let utxo1_address = handle_error!(private_key1.to_address(&BitcoinFormat::Bech32));
        let public_key1 = private_key1
            .to_public_key()
            .to_secp256k1_public_key()
            .serialize_compressed()
            .to_vec();

        let cpfp_input =
            transactions::btc::form_transaction_input::<N>(&input1, &utxo1_address, &public_key1)
                .unwrap();

        let address_format = match input2.address_format.as_str() {
            "p2pkh" => BitcoinFormat::P2PKH,
            "p2wpkh" => BitcoinFormat::Bech32,
            "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
            "p2wsh" => BitcoinFormat::P2WSH,
            _ => return Err(format!("not supported address format specified")),
        };

        let utxo2_address = handle_error!(private_key2.to_address(&address_format));
        let public_key2 = private_key2
            .to_public_key()
            .to_secp256k1_public_key()
            .serialize_compressed()
            .to_vec();

        let utxo_input =
            transactions::btc::form_transaction_input::<N>(&input2, &utxo2_address, &public_key2)
                .unwrap();

        // add P2WPKH output
        let output_script_pubkey = create_p2wpkh_scriptpubkey::<N>(&output.pubkey, false);
        let p2wpkh_output = BitcoinTransactionOutput {
            amount: BitcoinAmount(output.amount),
            script_pub_key: output_script_pubkey,
        };

        // now we can sign the second utxo
        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: vec![cpfp_input, utxo_input],
            outputs: vec![p2wpkh_output],
            lock_time: lock_time,
            segwit_flag: true,
        };
        let transaction = handle_error!(BitcoinTransaction::<N>::new(&transaction_parameters));
        let half_signed_tx = match transaction.sign(&private_key1) {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to sign transaction: {:?}", e)),
        };

        let full_signed_tx = match half_signed_tx.sign(&private_key2) {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to sign transaction: {:?}", e)),
        };

        let signed_tx_bytes = handle_error!(full_signed_tx.to_transaction_bytes());
        let txid_str = handle_error!(full_signed_tx.to_transaction_id());
        let txid_bytes = handle_error!(hex::decode(txid_str.to_string()));
        Ok((signed_tx_bytes, txid_bytes))
    }
}

/* Zcash transactions - shielded and transparent */
pub mod zec {}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Testnet;
    use std::str::FromStr;
    use transactions::{MultiSigOutput, Output, UtxoInput};

    #[test]
    fn test_variable_self_delay() {
        let self_delay_le = vec![0x01, 0x01]; // 257 and above
        let self_delay_bytes = transactions::btc::encode_self_delay(&self_delay_le).unwrap();
        assert_eq!(self_delay_bytes, vec![0x02, 0x01, 0x01]);

        let self_delay_le2 = vec![0x7f, 0x00]; // 127
        let self_delay_bytes2 = transactions::btc::encode_self_delay(&self_delay_le2).unwrap();
        assert_eq!(self_delay_bytes2, vec![0x01, 0x7f]);

        let self_delay_le3 = vec![0x10, 0x00]; // 16
        let self_delay_bytes3 = transactions::btc::encode_self_delay(&self_delay_le3).unwrap();
        assert_eq!(self_delay_bytes3, vec![0x60]);

        // failure case
        let self_delay_le4 = vec![0x00, 0x00]; // 0
        let self_delay_bytes4 = transactions::btc::encode_self_delay(&self_delay_le4);
        assert!(self_delay_bytes4.is_err());
    }

    #[test]
    fn bitcoin_p2wsh_address() {
        let expected_scriptpubkey =
            hex::decode("0020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd")
                .unwrap();
        let pubkey1 =
            hex::decode("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1")
                .unwrap();
        let pubkey2 =
            hex::decode("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb")
                .unwrap();
        let output_scriptpubkey =
            transactions::btc::create_p2wsh_scriptpubkey::<Testnet>(&pubkey1, &pubkey2);

        println!(
            "expected script_pubkey: {}",
            hex::encode(&output_scriptpubkey)
        );

        assert_eq!(output_scriptpubkey, expected_scriptpubkey);
    }

    #[test]
    fn bitcoin_testnet_escrow_tx() {
        let input = UtxoInput {
            address_format: String::from("p2sh_p2wpkh"),
            transaction_id: hex::decode(
                "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1",
            )
            .unwrap(),
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(40 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let musig_output = MultiSigOutput {
            merch_pubkey: hex::decode(
                "027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb",
            )
            .unwrap(),
            cust_pubkey: hex::decode(
                "037bed6ab680a171ef2ab564af25eff15c0659313df0bbfb96414da7c7d1e65882",
            )
            .unwrap(),
            address_format: "p2wsh",
            amount: 39 * SATOSHI,
        };

        // address => "n1Z8M5eoimzqvAmufqrSXFAGzKtJ8QoDnD"
        // private_key => "cVKYvWfApKiQJjLJhHokq7eEEFcx8Y1vsJYE9tVb5ccj3ZaCY82X" // testnet
        let change_output = ChangeOutput {
            pubkey: hex::decode(
                "021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67",
            )
            .unwrap(),
            amount: (1 * SATOSHI),
            is_hash: false,
        };

        let private_key = BitcoinPrivateKey::<Testnet>::from_str(
            "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn",
        )
        .unwrap();
        let (escrow_tx_preimage, full_escrow_tx) =
            transactions::btc::create_escrow_transaction::<Testnet>(
                &input,
                0,
                &musig_output,
                &change_output,
                private_key.clone(),
            )
            .unwrap();

        let expected_escrow_preimage = "020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4000000001976a914a496306b960746361e3528534d04b1ac4726655a88ac00286bee00000000ffffffff51bbd879074a16332d89cd524d8672b9cbe2096ed6825847141b9798cb915ad80000000001000000";

        // println!("escrow tx raw preimage: {}", hex::encode(&escrow_tx_preimage));
        // println!("escrow tx: {}", full_escrow_tx);
        assert_eq!(
            escrow_tx_preimage,
            hex::decode(expected_escrow_preimage).unwrap()
        );
        let (signed_tx, txid, hash_prevout) =
            transactions::btc::sign_escrow_transaction(full_escrow_tx, private_key);
        println!("signed_tx: {}", hex::encode(signed_tx));
        println!("txid: {}", hex::encode(txid));
        println!("hash prevout: {}", hex::encode(hash_prevout));
    }

    #[test]
    fn bitcoin_serialize_utxo_input() {
        let input = UtxoInput {
            address_format: String::from("p2sh_p2wpkh"),
            transaction_id: hex::decode(
                "cf6f93e3367f9925de957303af97b4be67060437bde3785d6b465d19ebac861b",
            )
            .unwrap(),
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(3 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let ser_input = serde_json::to_string(&input).unwrap();

        println!("Ser input: {:?}", &ser_input);

        let rec_input: UtxoInput = serde_json::from_str(&ser_input).unwrap();
        assert_eq!(input, rec_input);
    }

    #[test]
    fn bitcoin_testnet_dual_funded_escrow_tx() {
        let cust_input = UtxoInput {
            address_format: String::from("p2sh_p2wpkh"),
            transaction_id: hex::decode(
                "cf6f93e3367f9925de957303af97b4be67060437bde3785d6b465d19ebac861b",
            )
            .unwrap(),
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(3 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let merch_input = UtxoInput {
            address_format: String::from("p2sh_p2wpkh"),
            transaction_id: hex::decode(
                "bf6f93e3367f9925de957303af97b4be67060437bde3785d6b465d19ebac861f",
            )
            .unwrap(),
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(4 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let cust_private_key = BitcoinPrivateKey::<Testnet>::from_str(
            "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn",
        )
        .unwrap();

        let merch_private_key = BitcoinPrivateKey::<Testnet>::from_str(
            "cNTSD7W8URSCmfPTvNf2B5gyKe2wwyNomkCikVhuHPCsFgBUKrAV",
        )
        .unwrap();

        let cust_address = cust_private_key
            .to_address(&BitcoinFormat::P2SH_P2WPKH)
            .unwrap();
        let cust_input_pk = cust_private_key
            .to_public_key()
            .to_secp256k1_public_key()
            .serialize_compressed()
            .to_vec();

        let mut cust_tx_input = transactions::btc::form_transaction_input::<Testnet>(
            &cust_input,
            &cust_address,
            &cust_input_pk,
        )
        .unwrap();

        let merch_address = merch_private_key
            .to_address(&BitcoinFormat::P2SH_P2WPKH)
            .unwrap();
        let merch_input_pk = merch_private_key
            .to_public_key()
            .to_secp256k1_public_key()
            .serialize_compressed()
            .to_vec();

        let merch_tx_input = transactions::btc::form_transaction_input::<Testnet>(
            &merch_input,
            &merch_address,
            &merch_input_pk,
        )
        .unwrap();

        // output 1 - multi-sig
        let musig_output = MultiSigOutput {
            merch_pubkey: hex::decode(
                "021df2e472ce4f5f76100a45f04f75bf8742a796a07a6abfc8ed2b9939588b981a",
            )
            .unwrap(),
            cust_pubkey: hex::decode(
                "0250a33b5a379c2143c7deb27345a4f16d6f766fbf31c4a477e64050b5ec506f03",
            )
            .unwrap(),
            address_format: "p2wsh",
            amount: 4 * SATOSHI,
        };

        let cust_change_output = ChangeOutput {
            pubkey: hex::decode(
                "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
            )
            .unwrap(),
            amount: (1 * SATOSHI),
            is_hash: false,
        };

        let merch_change_output = ChangeOutput {
            pubkey: hex::decode(
                "02bf610ccd27d24b9718abb272fef97d3d342f083b3c6d495c05d98c0dd875fe41",
            )
            .unwrap(),
            amount: (2 * SATOSHI),
            is_hash: false,
        };

        let change_outputs = vec![cust_change_output, merch_change_output];

        // test forming tx preimage for customer side
        let inputs = vec![cust_tx_input.clone(), merch_tx_input.clone()];
        let (cust_tx_preimage, _) = transactions::btc::form_dual_escrow_transaction(
            &inputs,
            0,
            &musig_output,
            &change_outputs,
        )
        .unwrap();

        let expected_cust_preimage = "0200000001ffca6fcff6dce2963645252d5ff62ca3cf5a96a0e2ca01843f3080cddec56d752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad1b86aceb195d466b5d78e3bd37040667beb497af037395de25997f36e3936fcf000000001976a914a496306b960746361e3528534d04b1ac4726655a88ac00a3e11100000000ffffffff383ecd581d0ebd249748cc736d6e333d55d2f1c413c458233eeb7a677f6a7c880000000001000000";
        assert_eq!(expected_cust_preimage, hex::encode(&cust_tx_preimage));
        println!("Tx preimage (cust) => {}", hex::encode(&cust_tx_preimage));

        // TODO: add a method to form/get txid for escrow transaction

        // let's sign the dual escrow transaction
        let (cust_signature, cust_public_key) =
            transactions::btc::cust_sign_dual_escrow_transaction::<Testnet>(
                &inputs,
                0,
                &musig_output,
                &change_outputs,
                &cust_private_key,
            )
            .unwrap();

        println!("Tx Signature: {}", hex::encode(&cust_signature));

        // add signature and public key to input struct
        // if p2sh_p2wpkh
        cust_tx_input
            .witnesses
            .append(&mut vec![cust_signature.clone(), cust_public_key.clone()]);
        let input_script = match &cust_tx_input.outpoint.redeem_script {
            Some(redeem_script) => redeem_script.clone(),
            None => panic!("Invalid input_script!"),
        };
        cust_tx_input.script_sig = [vec![input_script.len() as u8], input_script].concat();
        cust_tx_input.is_signed = true;

        // include updated cust_tx_input (with witness)
        let input_vec = vec![cust_tx_input.clone(), merch_tx_input.clone()];

        // merchant moves forward to sign their UTXO as well
        let (_, escrow_unsigned_tx) = transactions::btc::form_dual_escrow_transaction(
            &input_vec,
            1,
            &musig_output,
            &change_outputs,
        )
        .unwrap();

        let signed_escrow_tx = escrow_unsigned_tx.sign(&merch_private_key).unwrap();
        let signed_escrow_tx_raw = signed_escrow_tx.to_transaction_bytes().unwrap();
        println!("signed_tx: {}", hex::encode(signed_escrow_tx_raw));

        // let (merch_tx_preimage, _) = transactions::btc::form_dual_escrow_transaction(&inputs, 1, &musig_output, &change_outputs).unwrap();
        // let expected_merch_preimage = "0200000001ffca6fcff6dce2963645252d5ff62ca3cf5a96a0e2ca01843f3080cddec56d752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad1f86aceb195d466b5d78e3bd37040667beb497af037395de25997f36e3936fbf000000001976a91475a4b47419fc5103559444c28cca8e2b04f7680688ac0084d71700000000ffffffff383ecd581d0ebd249748cc736d6e333d55d2f1c413c458233eeb7a677f6a7c880000000001000000";
        // assert_eq!(expected_merch_preimage, hex::encode(&merch_tx_preimage));
        // println!("Tx preimage (merch) => {}", hex::encode(merch_tx_preimage));
    }

    #[test]
    fn bitcoin_testnet_merch_close_tx() {
        // construct redeem script for this transaction to be able to spend from escrow-tx
        let cust_pk =
            hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb")
                .unwrap();
        let cust_private_key = "cNTSD7W8URSCmfPTvNf2B5gyKe2wwyNomkCikVhuHPCsFgBUKrAV";
        let merch_pk =
            hex::decode("03af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb353")
                .unwrap();
        let merch_private_key = "cNTSD7W8URSCmfPTvNf2B5gyKe2wwyNomkCikVhuHPCsFgBUKrAV"; // testnet
        let merch_close_pk =
            hex::decode("02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af")
                .unwrap();
        let merch_child_pk =
            hex::decode("03e9e77514212c68df25a35840eceba9d2a68359d46903a224b07d66b55ffc77d8")
                .unwrap();

        let expected_redeem_script = hex::decode("522103af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb35321027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae").unwrap();
        let redeem_script =
            transactions::btc::serialize_p2wsh_escrow_redeem_script(&cust_pk, &merch_pk);

        println!("expected redeem_script: {}", hex::encode(&redeem_script));
        assert_eq!(redeem_script, expected_redeem_script);

        // customer private key
        let input = UtxoInput {
            address_format: String::from("p2wsh"),
            // outpoint + txid
            transaction_id: hex::decode(
                "5eb0c50e6f725b88507cda84f339aba539bc99853436db610d6a476a207f82d9",
            )
            .unwrap(),
            index: 0,
            redeem_script: Some(redeem_script),
            script_pub_key: None,
            utxo_amount: Some(10 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let to_self_delay: [u8; 2] = [0x05, 0xcf]; // big-endian format
        let fee_mc = 1 * SATOSHI;
        let val_cpfp = 1 * SATOSHI;

        let c_private_key = BitcoinPrivateKey::<Testnet>::from_str(cust_private_key).unwrap();
        let m_private_key = BitcoinPrivateKey::<Testnet>::from_str(merch_private_key).unwrap();
        let tx_params = transactions::btc::create_merch_close_transaction_params::<Testnet>(
            &input,
            fee_mc,
            val_cpfp,
            &cust_pk,
            &merch_pk,
            &merch_close_pk,
            &merch_child_pk,
            &to_self_delay,
        )
        .unwrap();

        let (merch_tx_preimage, _) =
            transactions::btc::create_merch_close_transaction_preimage::<Testnet>(&tx_params)
                .unwrap();
        println!(
            "merch-close tx raw preimage: {}",
            hex::encode(&merch_tx_preimage)
        );
        let expected_merch_tx_preimage = hex::decode("02000000fdd1def69203bbf96a6ebc56166716401302fcd06eadd147682e8898ba19bee43bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044d9827f206a476a0d61db36348599bc39a5ab39f384da7c50885b726f0ec5b05e0000000047522103af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb35321027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae00ca9a3b00000000ffffffff9fd02e61301487e3261a481363e334d58818d18b7578bc9db28ac6f3ea18bbf00000000001000000").unwrap();
        assert_eq!(merch_tx_preimage, expected_merch_tx_preimage);

        // customer signs the preimage and sends signature to merchant
        let cust_signature = transactions::btc::generate_signature_for_multi_sig_transaction::<
            Testnet,
        >(&merch_tx_preimage, &c_private_key)
        .unwrap();

        // merchant takes the signature and signs the transaction
        let (signed_merch_close_tx, txid, hash_prevout) =
            transactions::btc::completely_sign_multi_sig_transaction::<Testnet>(
                &tx_params,
                &cust_signature,
                false,
                None,
                &m_private_key,
            );
        let merch_tx = hex::encode(signed_merch_close_tx.to_transaction_bytes().unwrap());
        println!("========================");
        println!("merch-close signed_tx: {}", merch_tx);
        println!("========================");
        println!("txid: {}", hex::encode(txid));
        println!("hash prevout: {}", hex::encode(hash_prevout));
        println!("========================");
    }

    #[test]
    fn bitcoin_testnet_cust_close_from_escrow_tx() {
        let spend_from_escrow = true;
        let input = UtxoInput {
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
        let cust_private_key = "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn"; // for cust-pk
        let merch_private_key = "cNTSD7W8URSCmfPTvNf2B5gyKe2wwyNomkCikVhuHPCsFgBUKrAV"; // for merch-pk
        let mut pubkeys = ClosePublicKeys {
            cust_pk: hex::decode(
                "027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb",
            )
            .unwrap(),
            cust_close_pk: hex::decode(
                "027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb",
            )
            .unwrap(),
            merch_pk: hex::decode(
                "03af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb353",
            )
            .unwrap(),
            merch_close_pk: hex::decode(
                "02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af",
            )
            .unwrap(),
            merch_child_pk: hex::decode(
                "03e9e77514212c68df25a35840eceba9d2a68359d46903a224b07d66b55ffc77d8",
            )
            .unwrap(),
            merch_disp_pk: hex::decode(
                "021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67",
            )
            .unwrap(),
            rev_lock: FixedSizeArray32([0u8; 32]),
        };
        let rev_lock =
            hex::decode("3111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        pubkeys.rev_lock.0.copy_from_slice(&rev_lock);

        let cust_bal = 8 * SATOSHI;
        let merch_bal = 2 * SATOSHI;
        let fee_cc = 1 * SATOSHI;
        let fee_mc = 1 * SATOSHI;
        let val_cpfp = 1 * SATOSHI;
        let to_self_delay: [u8; 2] = [0x05, 0xcf]; // big-endian format
        let (tx_preimage, tx_params, _) =
            transactions::btc::create_cust_close_transaction::<Testnet>(
                &input,
                &pubkeys,
                &to_self_delay,
                cust_bal,
                merch_bal,
                fee_cc,
                fee_mc,
                val_cpfp,
                spend_from_escrow,
            )
            .unwrap();
        println!(
            "cust-close from escrow tx raw preimage: {}",
            hex::encode(&tx_preimage)
        );
        let expected_tx_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff40000000047522103af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb35321027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae00ca9a3b00000000ffffffffc99bb6a5f54ca45860551116f8e20ca94a804827dec90fc5deeb4c758281d2060000000001000000").unwrap();
        assert_eq!(tx_preimage, expected_tx_preimage);

        // merchant signs the preimage (note this would happen via MPC)
        let m_private_key = BitcoinPrivateKey::<Testnet>::from_str(merch_private_key).unwrap();
        let merch_signature = transactions::btc::generate_signature_for_multi_sig_transaction::<
            Testnet,
        >(&tx_preimage, &m_private_key)
        .unwrap();

        // customer signs the transaction and embed the merch-signature
        let c_private_key = BitcoinPrivateKey::<Testnet>::from_str(cust_private_key).unwrap();
        let (signed_cust_close_tx, txid, hash_prevout) =
            transactions::btc::completely_sign_multi_sig_transaction::<Testnet>(
                &tx_params,
                &merch_signature,
                false,
                None,
                &c_private_key,
            );
        let cust_close_tx = hex::encode(signed_cust_close_tx.to_transaction_bytes().unwrap());

        println!("========================");
        println!("cust-close-from-escrow signed_tx: {}", cust_close_tx);
        println!("========================");
        println!("txid: {}", hex::encode(txid));
        println!("hash prevout: {}", hex::encode(hash_prevout));
        println!("========================");
    }

    #[test]
    fn bitcoin_testnet_cust_close_from_merch_tx() {
        let spend_from_escrow = false;
        let input = UtxoInput {
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

        let mut pubkeys = ClosePublicKeys {
            cust_pk: hex::decode(
                "027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb",
            )
            .unwrap(),
            cust_close_pk: hex::decode(
                "027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb",
            )
            .unwrap(),
            merch_pk: hex::decode(
                "024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b1",
            )
            .unwrap(),
            merch_close_pk: hex::decode(
                "02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af",
            )
            .unwrap(),
            merch_child_pk: hex::decode(
                "03e9e77514212c68df25a35840eceba9d2a68359d46903a224b07d66b55ffc77d8",
            )
            .unwrap(),
            merch_disp_pk: hex::decode(
                "021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67",
            )
            .unwrap(),
            rev_lock: FixedSizeArray32([0u8; 32]),
        };
        let rev_lock =
            hex::decode("3111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        pubkeys.rev_lock.0.copy_from_slice(&rev_lock);

        let cust_bal = 8 * SATOSHI;
        let merch_bal = 2 * SATOSHI;
        let fee_cc = 1 * SATOSHI;
        let fee_mc = 1 * SATOSHI;
        let val_cpfp = 1 * SATOSHI;
        let to_self_delay_be: [u8; 2] = [0x05, 0xcf]; // big-endian format
        let (tx_preimage, _, _) = transactions::btc::create_cust_close_transaction::<Testnet>(
            &input,
            &pubkeys,
            &to_self_delay_be,
            cust_bal,
            merch_bal,
            fee_cc,
            fee_mc,
            val_cpfp,
            spend_from_escrow,
        )
        .unwrap();
        println!(
            "cust-close from merch tx raw preimage: {}",
            hex::encode(&tx_preimage)
        );
        let expected_tx_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff40000000072635221024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b121027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae6702cf05b2752102ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5afac6800ca9a3b00000000ffffffff99a84d14a96ae4e80f5969402d4d39b14696b8c33901d642f6ab0618540ef8a90000000001000000").unwrap();
        assert_eq!(tx_preimage, expected_tx_preimage);
    }

    #[test]
    fn sign_merch_dispute_transaction() {
        // testing merchant dispute the `to_customer` output in the cust-close-*-tx during dispute period (via timelock)
        let txid_le =
            hex::decode("f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1")
                .unwrap();
        let index = 0;
        let input_sats = 1 * SATOSHI;
        let output_sats = 1 * SATOSHI;
        let rev_secret =
            hex::decode("3111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let rev_lock = Sha256::digest(&rev_secret).to_vec();
        let merch_disp_pk =
            hex::decode("021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67")
                .unwrap();
        let cust_close_pk =
            hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb")
                .unwrap();
        let to_self_delay_be: [u8; 2] = [0x05, 0xcf]; // big-endian format
        let output = Output {
            amount: output_sats,
            pubkey: hex::decode(
                "027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb",
            )
            .unwrap(),
        };

        let m_private_key = BitcoinPrivateKey::<Testnet>::from_str(
            "cNTSD7W8URSCmfPTvNf2B5gyKe2wwyNomkCikVhuHPCsFgBUKrAV",
        )
        .unwrap();

        let (signed_tx, tx_preimage) = transactions::btc::sign_merch_dispute_transaction_helper(
            txid_le,
            index,
            input_sats,
            output,
            to_self_delay_be,
            rev_lock,
            rev_secret,
            merch_disp_pk,
            cust_close_pk,
            m_private_key,
        )
        .unwrap();

        println!("preimage merch_dispue tx: {}", hex::encode(&tx_preimage));
        println!("signed merch_dispute tx: {}", hex::encode(&signed_tx));
        let expected_tx_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4000000007063a820192353284afd64b5a40e0cf61e81a914eb0fe441867bbb4f255095e1c14bd3f58821027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb6702cf05b27521021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe6768ac00e1f50500000000fffffffff80c36c55d65a6c94b50753f32e6d75cfc64d03f96d52d1b882bd1492d7a46180000000001000000").unwrap();
        assert_eq!(tx_preimage, expected_tx_preimage);
    }

    #[test]
    fn sign_cust_claim_transaction() {
        // testing customer claiming the `to_customer` output in the cust-close-*tx after timelock
        let txid_le =
            hex::decode("f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1")
                .unwrap();
        let index = 0;
        let input_sats = 1 * SATOSHI;
        let output_sats = 1 * SATOSHI;
        let rev_lock =
            hex::decode("3111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let merch_disp_pk =
            hex::decode("021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67")
                .unwrap();
        let cust_close_pk =
            hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb")
                .unwrap();
        let to_self_delay_be: [u8; 2] = [0x05, 0xcf]; // big-endian format

        let output = Output {
            amount: output_sats,
            pubkey: hex::decode(
                "027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb",
            )
            .unwrap(),
        };

        let c_private_key = BitcoinPrivateKey::<Testnet>::from_str(
            "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn",
        )
        .unwrap();
        let (signed_tx, txid) = transactions::btc::sign_cust_close_claim_transaction_helper(
            txid_le,
            index,
            input_sats,
            c_private_key,
            None,
            None,
            output,
            to_self_delay_be,
            rev_lock,
            merch_disp_pk,
            cust_close_pk,
        )
        .unwrap();
        println!("Txid : {}", hex::encode(&txid));
        println!("Signed tx: {}", hex::encode(signed_tx));
        assert_eq!(
            hex::encode(&txid),
            "63c9f765d8d14d60b951aba4b54bd38818186c9396cf8560500a2af989e3f519"
        );
    }

    #[test]
    fn sign_merch_claim_transactions() {
        // case 1 - testing merchant claiming the `to_merchant` output in the cust-close-*-tx (spendable immediately)
        let input_sats = 1 * SATOSHI;
        let output_sats = 1 * SATOSHI;
        let input1 = UtxoInput {
            address_format: String::from("p2wpkh"),
            // outpoint + txid
            transaction_id: hex::decode(
                "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1",
            )
            .unwrap(),
            index: 1,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(input_sats),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let output = Output {
            amount: output_sats,
            pubkey: hex::decode(
                "027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb",
            )
            .unwrap(),
        };

        let m_private_key = BitcoinPrivateKey::<Testnet>::from_str(
            "cNTSD7W8URSCmfPTvNf2B5gyKe2wwyNomkCikVhuHPCsFgBUKrAV",
        )
        .unwrap();
        let (signed_tx1, _tx_preimage1) = transactions::btc::sign_merch_claim_transaction_helper(
            input1,
            output.clone(),
            m_private_key.clone(),
            None,
            None,
        )
        .unwrap();
        println!("Spend from P2WPKH: {}", hex::encode(signed_tx1));

        // case 2 - testing merchant claiming the `merch-close-tx` output after timelock
        let cust_pk =
            hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb")
                .unwrap();
        let merch_pk =
            hex::decode("024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b1")
                .unwrap();
        let merch_close_pk =
            hex::decode("02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af")
                .unwrap();
        let to_self_delay_le: [u8; 2] = [0xcf, 0x05]; // little-endian format

        let redeem_script = transactions::btc::serialize_p2wsh_merch_close_redeem_script(
            &cust_pk,
            &merch_pk,
            &merch_close_pk,
            &to_self_delay_le.to_vec(),
        )
        .unwrap();

        let input2 = UtxoInput {
            address_format: String::from("p2wsh"),
            // outpoint + txid
            transaction_id: hex::decode(
                "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1",
            )
            .unwrap(),
            index: 0,
            redeem_script: Some(redeem_script),
            script_pub_key: None,
            utxo_amount: Some(output_sats),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let (signed_tx2, _tx_preimage2) = transactions::btc::sign_merch_claim_transaction_helper(
            input2,
            output,
            m_private_key,
            None,
            None,
        )
        .unwrap();
        println!("Spend from P2WSH: {}", hex::encode(signed_tx2));
    }
}
