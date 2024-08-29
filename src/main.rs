use base64::prelude::*;
use chrono::{TimeZone, Utc};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Serialize, Deserialize, Debug)]
struct Output {
    endpoint: Endpoint,
    reserved_str: String,
    reserved_hex: String,
    reserved_dec: Vec<i32>,
    private_key: String,
    public_key: String,
    addresses: Addresses,
}

#[derive(Serialize, Deserialize, Debug)]
struct Endpoint {
    v4: String,
    v6: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Addresses {
    v4: String,
    v6: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = StaticSecret::random_from_rng(&mut OsRng);
    let public = PublicKey::from(&secret);
    let public = BASE64_STANDARD.encode(public);
    let secret = BASE64_STANDARD.encode(secret);
    let body = ureq::post("https://api.cloudflareclient.com/v0a2158/reg")
        .set("CF-Client-Version", "a-7.13-0713")
        .set("Content-Type", "application/json")
        .send_string(
            json!({
                        "key": public,
                        "tos": format!("{}", Utc.with_ymd_and_hms(2020, 11, 10, 0, 1, 32).unwrap().format("%Y-%m-%dT%H:%M:%S.000Z"))
            }).to_string().as_str()
        )?
        .into_string()?;
    let data: Value = serde_json::from_str(body.as_str())?;
    let endpoint: Endpoint = serde_json::from_value(
        data["config"]["peers"].as_array().unwrap()[0]["endpoint"].to_owned(),
    )?;
    let addresses: Addresses =
        serde_json::from_value(data["config"]["interface"]["addresses"].to_owned())?;
    let client_id: String = serde_json::from_value(data["config"]["client_id"].to_owned())?;
    let hex_string = hex::encode(&BASE64_STANDARD.decode(&client_id)?);
    let mut dec_values: Vec<i32> = Vec::new();
    for i in (0..hex_string.len()).step_by(2) {
        let hex_byte = &hex_string[i..i + 2];
        let dec_value = u8::from_str_radix(hex_byte, 16)? as i32;
        dec_values.push(dec_value / 100 * 100 + (dec_value / 10 % 10) * 10 + dec_value % 10);
    }
    println!("{}", serde_json::to_string_pretty(&Output {
        endpoint: endpoint,
        reserved_str: client_id,
        reserved_hex: hex_string,
        reserved_dec: dec_values,
        private_key: secret,
        public_key: public,
        addresses: addresses,
    })?);
    Ok(())
}
