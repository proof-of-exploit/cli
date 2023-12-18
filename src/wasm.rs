use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{verify_proof, VerifyingKey};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer};
use halo2_proofs::SerdeFormat;
use js_sys::Uint8Array;
use std::io::BufReader;
use wasm_bindgen::prelude::*;
use zkevm_circuits::super_circuit::{SuperCircuit, SuperCircuitParams};

const SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

#[wasm_bindgen]
pub fn verify(
    proof_js: JsValue,
    params_js: JsValue,
    vk_js: JsValue,
    instance_0: JsValue,
    instance_1: JsValue,
) -> bool {
    console_error_panic_hook::set_once();

    #[allow(deprecated)]
    let proof_vec = proof_js.into_serde::<Vec<u8>>().unwrap();
    let params_vec = Uint8Array::new(&params_js).to_vec();
    let vk_vec = Uint8Array::new(&vk_js).to_vec();
    let mut instance_0 = instance_0.into_serde::<[u8; 32]>().unwrap();
    let mut instance_1 = instance_1.into_serde::<[u8; 32]>().unwrap();

    let params =
        ParamsKZG::<Bn256>::read_custom(&mut BufReader::new(&params_vec[..]), SERDE_FORMAT)
            .unwrap();

    let vk = VerifyingKey::<G1Affine>::read::<BufReader<&[u8]>, SuperCircuit<Fr>>(
        &mut BufReader::new(&vk_vec[..]),
        SERDE_FORMAT,
        SuperCircuitParams {
            mock_randomness: Fr::from(0x100),
        },
    )
    .unwrap();

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_vec[..]);

    instance_0.reverse();
    instance_1.reverse();

    let instances = vec![
        vec![
            Fr::from_bytes(&instance_0).unwrap(),
            Fr::from_bytes(&instance_1).unwrap(),
        ],
        vec![],
    ];
    let instances = instances.iter().map(|v| &v[..]).collect::<Vec<&[Fr]>>();

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&params, &vk, strategy, &[&instances], &mut transcript)
    .is_ok()
}

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}
