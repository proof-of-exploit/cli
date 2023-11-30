use std::{fs::File, io::Write};

use super::halo2::proof::Proof;
use crate::error::Error;
use pinata_sdk::{PinByFile, PinByJson, PinataApi};
use reqwest;

fn pinata() -> PinataApi {
    PinataApi::new(
        // temp api key only allows pinning json, TODO allow passing own api key
        "d18a79ccbf06647b8d2e",
        "a44539bbc32ea2806a635a94070f74a9d70bcb24a2b9ef921881912f85d7c6ba",
    )
    .unwrap()
}

pub async fn publish(proof: &Proof) -> Result<String, Error> {
    let pinned_object = pinata().pin_json(PinByJson::new(proof)).await?;
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

pub async fn publish_file(path: String) -> Result<String, Error> {
    let file = PinByFile::new(path);
    let hash = pinata().pin_file(file).await?.ipfs_hash;
    Ok(hash)
}

pub async fn download_file(hash: String, path: String) {
    let gateway = "https://gateway.pinata.cloud/ipfs/";

    let client = reqwest::Client::new();
    let res = client
        .get(gateway.to_owned() + hash.as_str())
        .send()
        .await
        .unwrap();

    let data = res.bytes().await.unwrap();
    let mut file = File::create(path).unwrap();
    file.write_all(&data).unwrap();
}
