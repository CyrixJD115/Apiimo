//! Game-gate topology: the public `server_list_publish.json` contract.
//!
//! The server list is published on a public CDN with no authentication
//! (`worldx-global-cdn.kingsgroupgames.com/server_list/server_list_publish.json`,
//! plus a backup host). It maps deployment groups (`Aniimo-OS`, `Aniimo-NA`,
//! review/QATT clusters, ...) to per-cluster HTTP directory addresses and
//! matchmaking-service gate addresses. The live client then resolves its
//! world gate (e.g. `worldx-us-prod-singleworld-1000-gate.kingsgroupgames.com`)
//! through the directory service and connects over KCP with an
//! encrypt-key-confirmation handshake (`GateClient.lua:onConfirmEncryptKeyAck`).
//!
//! Field names below match the published JSON exactly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::NetworkError;

/// The published server list document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerListPublish {
    /// Group name (`Aniimo-OS`, `Aniimo-NA`, `Review-Global`, ...) to group.
    #[serde(rename = "serverGroupData", alias = "server_group_data")]
    pub server_group_data: BTreeMap<String, ServerGroup>,
}

/// One deployment group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerGroup {
    #[serde(
        rename = "enableDefaultServerDetect",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub enable_default_server_detect: Option<bool>,
    /// Group-level HTTP directory addresses (clusters may override).
    #[serde(
        rename = "externalAddrList",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_addr_list: Option<Vec<ExternalAddr>>,
    /// Group-level matchmaking-service gate addresses (`host:port`).
    #[serde(
        rename = "msGateAddrList",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ms_gate_addr_list: Option<Vec<String>>,
    #[serde(rename = "localDirData", default)]
    pub local_dir_data: Vec<LocalDir>,
}

/// One cluster inside a group's directory data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalDir {
    #[serde(rename = "ClusterName")]
    pub cluster_name: String,
    #[serde(rename = "ClusterId")]
    pub cluster_id: i64,
    #[serde(
        rename = "externalAddrList",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_addr_list: Option<Vec<ExternalAddr>>,
    #[serde(
        rename = "msGateAddrList",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ms_gate_addr_list: Option<Vec<String>>,
}

/// An HTTP directory address for a cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAddr {
    #[serde(rename = "isSSL")]
    pub is_ssl: bool,
    #[serde(rename = "httpIp")]
    pub http_ip: String,
    #[serde(rename = "httpPort")]
    pub http_port: u16,
}

impl ServerListPublish {
    /// Parse the published JSON document.
    pub fn parse(json: &str) -> Result<Self, NetworkError> {
        serde_json::from_str(json)
            .map_err(|source| NetworkError::Xdf(format!("server list: {source}")))
    }

    /// Every matchmaking-service gate address in the document
    /// (`host:port` strings, group-level and per-cluster).
    pub fn all_ms_gates(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for group in self.server_group_data.values() {
            if let Some(gates) = &group.ms_gate_addr_list {
                out.extend(gates.iter().map(String::as_str));
            }
            for dir in &group.local_dir_data {
                if let Some(gates) = &dir.ms_gate_addr_list {
                    out.extend(gates.iter().map(String::as_str));
                }
            }
        }
        out
    }

    /// The group containing a cluster with the given `ClusterName`.
    pub fn group_with_cluster(&self, cluster: &str) -> Option<&ServerGroup> {
        self.server_group_data.values().find(|group| {
            group
                .local_dir_data
                .iter()
                .any(|d| d.cluster_name == cluster)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trimmed but structurally exact excerpt of the live
    // server_list_publish.json (fetched 2026-09-21).
    const FIXTURE: &str = r#"{
      "serverGroupData": {
        "Aniimo-OS": {
          "enableDefaultServerDetect": true,
          "localDirData": [
            {
              "externalAddrList": [
                {"httpIp": "worldx-eu-prod-external.kingsgroupgames.com", "httpPort": 19041, "isSSL": true}
              ],
              "msGateAddrList": ["eu-prod-ms.worldx-gate.kingsgroupgames.com:10000", "47.245.180.147:10000"],
              "ClusterName": "Aniimo-Europe",
              "ClusterId": 100
            }
          ]
        },
        "Aniimo-Russia": {
          "externalAddrList": [{"isSSL": false, "httpPort": 19041, "httpIp": "47.254.146.32"}],
          "msGateAddrList": ["47.254.146.32:26000"],
          "localDirData": [{"ClusterName": "Aniimo-Russia", "ClusterId": 100}]
        }
      }
    }"#;

    #[test]
    fn parses_live_server_list_shape() {
        let list = ServerListPublish::parse(FIXTURE).unwrap();
        assert_eq!(list.server_group_data.len(), 2);

        let os = &list.server_group_data["Aniimo-OS"];
        assert_eq!(os.enable_default_server_detect, Some(true));
        let europe = &os.local_dir_data[0];
        assert_eq!(europe.cluster_name, "Aniimo-Europe");
        assert_eq!(europe.cluster_id, 100);
        assert_eq!(
            europe.external_addr_list.as_deref().unwrap()[0].http_port,
            19041
        );
        assert!(europe.external_addr_list.as_deref().unwrap()[0].is_ssl);
        assert_eq!(
            europe.ms_gate_addr_list.as_deref().unwrap()[0],
            "eu-prod-ms.worldx-gate.kingsgroupgames.com:10000"
        );

        let russia = &list.server_group_data["Aniimo-Russia"];
        assert!(!russia.external_addr_list.as_deref().unwrap()[0].is_ssl);

        let gates = list.all_ms_gates();
        assert_eq!(gates.len(), 3);
        assert!(gates.contains(&"47.254.146.32:26000"));

        assert_eq!(
            list.group_with_cluster("Aniimo-Europe")
                .map(|g| g.local_dir_data.len()),
            Some(1)
        );
        assert!(list.group_with_cluster("nope").is_none());
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Set `APIIMO_SERVER_LIST=<path>` to validate the parser against a
    /// real fetched server_list_publish.json; skipped otherwise.
    #[test]
    fn parses_real_server_list_when_provided() {
        let Ok(path) = std::env::var("APIIMO_SERVER_LIST") else {
            return;
        };
        let json = std::fs::read_to_string(&path).unwrap();
        let list = ServerListPublish::parse(&json).unwrap();
        assert!(list.server_group_data.len() >= 10);
        assert!(list.all_ms_gates().len() >= 10);
        assert!(list.group_with_cluster("Aniimo-Americas").is_some());
    }
}
