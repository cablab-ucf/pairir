//! pairir's API for the page's worker (www/worker.js): text in and out as
//! bytes, on the lab's relays or, built with `PAIRIR_RELAY=<url>`, a
//! deployment's own (add it to the CSP's connect-src). Secrets and passwords
//! in are wiped once used; secrets out go straight to the page, no copy
//! left in wasm's memory.

#![forbid(unsafe_code)]

use js_sys::{Function, JsString, Uint8Array};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn relays() -> Vec<iroh::RelayUrl> {
    option_env!("PAIRIR_RELAY")
        .map(|r| r.parse().expect("PAIRIR_RELAY: a url"))
        .into_iter()
        .collect()
}

fn err(e: anyhow::Error) -> JsError {
    JsError::new(&format!("{e:#}"))
}

/// Gives `secret`: `on_code` gets the code at once; resolves to how it ended
/// (`Taken`, `Spent`, `Expired`).
#[wasm_bindgen]
pub async fn give(
    app: String,
    secret: Vec<u8>,
    password: Option<String>,
    on_code: Function,
) -> Result<String, JsError> {
    let (secret, password) = (Zeroizing::new(secret), Zeroizing::new(password));
    let (code, end) =
        pairir::give(&relays(), &app, &secret, password.as_deref()).await.map_err(err)?;
    on_code.call1(&JsValue::NULL, &JsString::from(code)).map_err(|_| JsError::new("on_code"))?;
    Ok(format!("{:?}", end.await.map_err(|e| JsError::new(&e.to_string()))?))
}

#[wasm_bindgen]
pub async fn take(
    app: String,
    code: String,
    password: Option<String>,
) -> Result<Uint8Array, JsError> {
    let password = Zeroizing::new(password);
    let s = pairir::take(&relays(), &app, &code, password.as_deref()).await.map_err(err)?;
    Ok(Uint8Array::from(&s[..]))
}

#[wasm_bindgen]
pub fn password() -> String {
    pairir::password()
}

#[wasm_bindgen]
pub async fn seal_qr(app: String, secret: Vec<u8>, password: String) -> Result<String, JsError> {
    let (secret, password) = (Zeroizing::new(secret), Zeroizing::new(password));
    pairir::seal_qr(&app, &secret, &password).await.map_err(err)
}

#[wasm_bindgen]
pub async fn open_qr(app: String, text: String, password: String) -> Result<Uint8Array, JsError> {
    let password = Zeroizing::new(password);
    Ok(Uint8Array::from(&pairir::open_qr(&app, &text, &password).await.map_err(err)?[..]))
}

/// `text` as a QR code's SVG, as the apps scan it.
#[wasm_bindgen]
pub fn qr_svg(text: String) -> Result<String, JsError> {
    let q = qrcode::QrCode::new(text).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(q.render::<qrcode::render::svg::Color>().min_dimensions(256, 256).build())
}
