use super::halo2::proof::Proof;
use crate::error::Error;
use pinata_sdk::{PinByJson, PinataApi};
use reqwest;

pub async fn publish(proof: &Proof) -> Result<String, Error> {
    let api = PinataApi::new(
        // temp api key only allows pinning json, TODO allow passing own api key
        "81ff4f65264d2a866926",
        "0f20f80d89da0d99071b59be83a88797f9d6c803ebd966ca3e401fec5a081030",
    )
    .unwrap();

    let pinned_object = api.pin_json(PinByJson::new(proof)).await?;
    Ok(pinned_object.ipfs_hash)
}

pub async fn get(hash: String) -> Result<Proof, Error> {
    let gateway = "https://gateway.pinata.cloud/ipfs/";

    let client = reqwest::Client::new();
    let res = client
        .get(gateway.to_owned() + hash.as_str())
        .send()
        .await
        .unwrap();

    let str = res.text().await.unwrap();
    Ok(serde_json::from_str(str.as_str())?)
}
