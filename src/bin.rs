use cid::Cid;
use ethers::prelude::*;
use Cid::cid;
use multihash::{MultihashDigest, Sha2_256};
use multiformats::{cid::Cid, multihash::MultihashDigest, multihash::Sha2_256};
use serde_json::json;
use std::error::Error;

mod dmap;

const GATEWAYS: &[&str] = &[
    "https://ipfs.fleek.co/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
    "https://storry.tv/ipfs/",
    "https://ipfs.io/ipfs/",
    "https://hub.textile.io/ipfs/",
];
const INFURA_URL: &str = "https://mainnet.infura.io/v3/c0a739d64257448f855847c6e3d173e1";
const PREF_LEN_INDEX: usize = 30;

struct Utils;

impl Utils {
    fn prepare_cid(cid_str: &str, lock: bool) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        let cid = Cid::from_str(cid_str)?;
        let hash_len = cid.hash().size();
        let prefix_len = cid.to_bytes().len() - hash_len;
        let mut meta = vec![0u8; 32];
        let mut data = vec![0u8; 32];

        data.splice(32 - hash_len..32, cid.hash().digest());
        meta.splice(0..prefix_len, cid.to_bytes().iter().take(prefix_len).copied());
        if lock {
            meta[31] |= dmap::DmapLib::FLAG_LOCK;
        }
        meta[PREF_LEN_INDEX] = prefix_len as u8;
        Ok((meta, data))
    }

    fn unpack_cid(meta_str: &str, data_str: &str) -> Result<String, Box<dyn Error>> {
        let meta = dmap::hex_to_array_buffer(meta_str);
        let data = dmap::hex_to_array_buffer(data_str);
        let prefix_len = meta[PREF_LEN_INDEX] as usize;
        let specs = Cid::inspect_bytes(&meta[..prefix_len])?;
        let hash_len = specs.hash_size;
        let mut cid_bytes = vec![0u8; prefix_len + hash_len];

        cid_bytes[..prefix_len].copy_from_slice(&meta[..prefix_len]);
        cid_bytes[prefix_len..].copy_from_slice(&data[32 - hash_len..]);
        let cid = Cid::try_from(cid_bytes)?;
        Ok(cid.to_string())
    }

    async fn read_cid(contract: &dmap::Dmap, path: &str) -> Result<String, Box<dyn Error>> {
        let packed = dmap::DmapLib::new(contract.address.clone(), contract.provider.clone())
            .walk(contract, path)
            .await?;
        Self::unpack_cid(&packed.0, &packed.1)
    }
}

async fn resolve_cid(cid: &str, target_digest: &str, node_address: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let verify = |bytes: &[u8]| async {
        let hash = Sha2_256::digest(bytes);
        let result_digest = serde_json::to_string(&hash.digest)?;
        Ok::<_, Box<dyn Error>>(target_digest == result_digest)
    };

    let url = format!("{}/api/v0/cat?arg={}", node_address, cid);
    let response = reqwest::post(&url).await?;
    let mut cat_response = response.bytes().await?;

    if verify(&cat_response).await? {
        return Ok(cat_response.to_vec());
    }

    for &gateway in GATEWAYS {
        let url = format!("{}{}", gateway, cid);
        let response = reqwest::get(&url).await?;
        let cat_response = response.bytes().await?;

        if verify(&cat_response).await? {
            return Ok(cat_response.to_vec());
        }
    }

    Err("unable to resolve cid".into())
}

async fn make_rpc(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, Box<dyn Error>> {
    let response = reqwest::Client::new()
        .post(url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 0
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    Ok(response["result"].clone())
}

async fn rpc_get_storage(url: &str, address: &str, slot: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let block = make_rpc(url, "eth_blockNumber", json!([])).await?;
    make_rpc(url, "eth_getStorageAt", json!([address, slot, block])).await
}

#[tokio::main]
async fn main() {
    let document = web_sys::window().unwrap().document().unwrap();
    let result = document.get_element_by_id("result").unwrap();
    let line = |s: &str| {
        result.set_inner_html(&format!("{}\n{}", result.inner_html(), s));
    };

    let eth_node = document.get_element_by_id("ethNode").unwrap();
    let dpath = document.get_element_by_id("dpath").unwrap();

    eth_node.add_event_listener_with_callback("click", &Closure::wrap(Box::new(move || {
        let eth_node_value = eth_node.value();
        let dpath_value = dpath.value();
        
        task::block_on(async {
            let custom_url = eth_node_value;
            let (dmap_facade, description) = get_facade(&custom_url).await.unwrap();

            line(&format!("(using {} for eth connection) \n", description));
            line(&format!("WALK {} \n", dpath_value));

            let walk_result = dmap::DmapLib::new(dmap_facade.address.clone(), dmap_facade.provider.clone())
                .walk2(&dmap_facade, &dpath_value)
                .await;

            match walk_result {
                Ok(walk_result) => {
                    for step in walk_result {
                        line("step");
                        line(&format!("  meta: {}", step.0));
                        line(&format!("  data: {}", step.1));
                    }
                    line("");
                    let last = walk_result.last().unwrap();
                    let cid = Utils::unpack_cid(&last.0, &last.1).unwrap();
                    line(&format!("ipfs: {}", cid));

                    let target_digest = serde_json::to_string(&Cid::from_str(&cid).unwrap().hash().digest).unwrap();
                    let resolved = resolve_cid(&cid, &target_digest, &eth_node_value).await.unwrap();

                    let utf8decoder = std::str::from_utf8(&resolved).unwrap();
                    line(utf8decoder);
                }
                Err(error) => {
                    line("");
                    line(&format!("FAIL: {}", error));
                }
            }
        });
    }) as Box<dyn FnMut()>).into_js_value()).unwrap();
}

async fn get_facade(custom_url: &str) -> Result<(dmap::Dmap, String), Box<dyn Error>> {
    let chain_id = make_rpc(custom_url, "eth_chainId", json!([])).await?;
    if chain_id == "0x1" {
        return Ok((dmap::Dmap { address: dmap::DmapLib::ADDRESS.to_string(), provider: rpc_get_storage(custom_url, "", "").await? }, "custom node".to_string()));
    }

    if let Some(ethereum) = web_sys::window().unwrap().ethereum() {
        let chain_id = ethereum.request(&json!({ "method": "eth_chainId" })).await?;
        if chain_id == "0x1" {
            return Ok((dmap::Dmap { address: dmap::DmapLib::ADDRESS.to_string(), provider: window_get_storage(ethereum).await? }, "window.ethereum".to_string()));
        }
    }

    let infura_chain_id = make_rpc(INFURA_URL, "eth_chainId", json!([])).await?;
    if infura_chain_id == "0x1" {
        return Ok((dmap::Dmap { address: dmap::DmapLib::ADDRESS.to_string(), provider: rpc_get_storage(INFURA_URL, "", "").await? }, "infura".to_string()));
    }

    Err("no ethereum connection".into())
}

async fn window_get_storage(ethereum: web_sys::Ethereum) -> Result<Provider<Http>, Box<dyn Error>> {
    let block = ethereum.request(&json!({ "method": "eth_blockNumber" })).await?;
    ethereum.request(&json!({ "method": "eth_getStorageAt", "params": ["", "", block] })).await?;
    Ok(Provider::try_from(INFURA_URL)?)
}