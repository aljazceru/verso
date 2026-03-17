use dioxus::prelude::*;
use serde_json::Value;
use serde_json::to_string as json_stringify;

#[component]
pub fn DetailsPanel(details: Value) -> Element {
    rsx! {
        div {
            class: "details-panel",
            {render_value(&details)}
        }
    }
}

fn render_value(v: &Value) -> Element {
    match v {
        Value::Object(map) => {
            let rows: Vec<Element> = map
                .iter()
                .map(|(key, val)| {
                    let key = key.clone();
                    let val_elem = render_value(val);
                    rsx! {
                        tr {
                            td { class: "detail-key", "{key}" }
                            td { class: "detail-value", {val_elem} }
                        }
                    }
                })
                .collect();
            rsx! {
                table { class: "details-table",
                    {rows.into_iter()}
                }
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                rsx! { span { class: "empty", "(none)" } }
            } else if arr.iter().all(|v| v.is_string()) {
                let items: Vec<Element> = arr
                    .iter()
                    .map(|item| {
                        let s = item.as_str().unwrap_or_default().to_string();
                        rsx! { li { "{s}" } }
                    })
                    .collect();
                rsx! {
                    ul { class: "detail-list",
                        {items.into_iter()}
                    }
                }
            } else {
                let divs: Vec<Element> = arr
                    .iter()
                    .map(|item| {
                        let inner = render_value(item);
                        rsx! { div { class: "array-item", {inner} } }
                    })
                    .collect();
                rsx! {
                    div { class: "detail-array",
                        {divs.into_iter()}
                    }
                }
            }
        }
        Value::String(s) => {
            if let Some((kind, url)) = classify_chain_value(s.as_str()) {
                let full = s.clone();
                let display = if s.len() > 36 {
                    format!("{}…{}", &s[..12], &s[s.len()-10..])
                } else {
                    s.clone()
                };
                let js_value = json_stringify(&full).unwrap_or_else(|_| "\"\"".to_string());
                let copy_js = format!("navigator.clipboard.writeText({js_value});");
                rsx! {
                    span { class: "chain-value-row",
                        a {
                            class: "chain-link",
                            href: "{url}",
                            target: "_blank",
                            rel: "noopener noreferrer",
                            title: format!("Open {kind} on mempool.space"),
                            "{display}"
                        }
                        button {
                            class: "copy-btn",
                            onclick: move |_| {
                                let _ = dioxus::document::eval(&copy_js);
                            },
                            "Copy"
                        }
                    }
                }
            } else {
                let s = s.clone();
                rsx! { span { "{s}" } }
            }
        }
        Value::Number(n) => {
            let n = n.to_string();
            rsx! { span { "{n}" } }
        }
        Value::Bool(b) => {
            let b = b.to_string();
            rsx! { span { "{b}" } }
        }
        Value::Null => rsx! { span { class: "null", "null" } },
    }
}

fn classify_chain_value(value: &str) -> Option<(&'static str, String)> {
    if is_txid(value) {
        Some(("transaction", format!("https://mempool.space/tx/{value}")))
    } else if is_address(value) {
        Some(("address", format!("https://mempool.space/address/{value}")))
    } else {
        None
    }
}

fn is_txid(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_address(value: &str) -> bool {
    is_base58_address(value) || is_bech32_address(value)
}

fn is_base58_address(value: &str) -> bool {
    let len = value.len();
    if !(26..=50).contains(&len) {
        return false;
    }
    let mut chars = value.chars();
    match chars.next() {
        Some('1' | '3' | '2' | 'm' | 'n' | 'M' | 'N') => {}
        _ => return false,
    }
    const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    value.chars().all(|c| ALPHABET.contains(c))
}

fn is_bech32_address(value: &str) -> bool {
    let value = value.to_lowercase();
    let len = value.len();
    let has_hrp = value.starts_with("bc1") || value.starts_with("tb1") || value.starts_with("bcrt1");
    if !has_hrp || !(14..=90).contains(&len) {
        return false;
    }
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    value.chars().skip(3).all(|c| CHARSET.contains(c))
}
