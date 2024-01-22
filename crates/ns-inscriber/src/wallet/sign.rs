use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};

use super::{skip_tag, with_tag, CoseSigner, CoseVerifier, SIGN1_TAG};

pub fn encode_sign1(
    signer: impl CoseSigner,
    payload: Vec<u8>,
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let protected = HeaderBuilder::new().algorithm(signer.alg()).build();
    let unprotected = HeaderBuilder::new().key_id(signer.kid()).build();

    let data = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload)
        .create_signature(aad, |data| signer.sign(data))
        .build()
        .to_vec()
        .map_err(anyhow::Error::msg)?;
    Ok(with_tag(&SIGN1_TAG, &data))
}

pub fn decode_sign1(
    verifier: impl CoseVerifier,
    sign1_data: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let msg =
        CoseSign1::from_slice(skip_tag(&SIGN1_TAG, sign1_data)).map_err(anyhow::Error::msg)?;
    msg.verify_signature(aad, |sig, data| verifier.verify(data, sig))?;
    msg.payload
        .ok_or_else(|| anyhow::Error::msg("missing payload"))
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use ns_protocol::ns::Value;

    use super::*;

    use crate::wallet::cose_key::KeyHelper;
    use crate::wallet::ed25519;

    #[test]
    fn sign1_works() {
        let secret = hex!("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3");
        let msg = b"This is the content.";
        let aad = hex!("11aa22bb33cc44dd55006699");
        let kid = Value::Text("11".to_string());
        let key = ed25519::Ed25519Key::from_secret(&secret, Some(kid.clone())).unwrap();
        assert_eq!(key.0.kid(), Some(kid.clone()));

        let signer = key.signer().unwrap();
        let output = encode_sign1(signer, msg.to_vec(), &aad).unwrap();
        assert_eq!(output, hex!("d28443a10127a1044362313154546869732069732074686520636f6e74656e742e584011319ba8e8508d613f5cc83bbb64d37e1b310582777ff8a7ec587c12879fb9a83c593167a65438d2e6a8906ea1da4296a8fcb5d1ebed9a6de157f1ba2257070d").to_vec());

        let verifier = key.verifier().unwrap();
        let msg2 = decode_sign1(verifier, &output, &aad).unwrap();
        assert_eq!(msg2.as_slice(), msg.as_slice());

        let pk = key.public().unwrap();
        assert_eq!(pk.0.kid(), Some(kid));
        assert_eq!(
            pk.get_public().unwrap().as_slice(),
            hex!("8373deeba9c0af9880e5c9e976ffda8522db9e3df20fddfe54b3a8c59cfe3c94").as_slice()
        );
        let verifier = pk.verifier().unwrap();
        let msg2 = decode_sign1(verifier, &output, &aad).unwrap();
        assert_eq!(msg2.as_slice(), msg.as_slice());
    }
}
