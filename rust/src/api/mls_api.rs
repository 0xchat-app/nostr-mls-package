use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use nostr_mls::prelude::*;
use nostr_mls::NostrMls;
use nostr_mls_sqlite_storage::NostrMlsSqliteStorage;
use serde_json::json;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

lazy_static! {
    static ref NOSTR_MLS: Mutex<Option<NostrMls<NostrMlsSqliteStorage>>> = Mutex::new(None);
}

/// Helper function to handle key package parsing errors
/// Returns a structured error message in JSON format if it's an InvalidLifetime error,
/// otherwise returns a generic error message
/// [member_pubkey] Optional pubkey of the member whose keypackage is being parsed
fn handle_key_package_parse_error(e: impl std::error::Error + Send + Sync + 'static, member_pubkey: Option<String>) -> anyhow::Error {
    // Convert to anyhow::Error first to check the error chain
    let anyhow_err = anyhow::Error::from(e);
    let error_str = format!("{:?}", anyhow_err);
    
    // Check if the error is KeyPackageVerifyError::InvalidLifetime
    // The error should contain "KeyPackageVerify" and "InvalidLifetime" in its debug representation
    if error_str.contains("The lifetime of the leaf node is not valid") {
        let mut error_json = json!({
            "error_type": "KEY_PACKAGE_INVALID_LIFETIME",
            "message": "The key package lifetime is invalid or expired"
        });
        
        // Add member_pubkey if provided
        if let Some(pubkey) = member_pubkey {
            error_json["member_pubkey"] = json!(pubkey);
        }
        
        anyhow::anyhow!("{}", error_json.to_string())
    } else {
        anyhow::anyhow!("Failed to parse key package: {}", anyhow_err)
    }
}

/// Initialize the NostrMls instance
/// Returns: JSON {"status": "success"} on success, or error message on failure
pub fn init_nostr_mls(path: String, identity: Option<String>, password: Option<String>) -> Result<String> {
    let mut mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;

    if let Some(old_mls) = mls.take() {
        drop(old_mls);
    }

    let db_path =
        PathBuf::from(path).join(identity.as_deref().unwrap_or("default").to_owned() + "-mls.db");

    let nostr_mls = NostrMls::new(
        NostrMlsSqliteStorage::new_with_password(db_path, password.as_deref())
            .map_err(|e| anyhow!("Failed to initialize storage: {}", e))?,
    );

    *mls = Some(nostr_mls);

    Ok(json!({"status": "success"}).to_string())
}

/// Get the current ciphersuite
/// Returns: JSON formatted ciphersuite information
pub fn get_ciphersuite() -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let ciphersuite = format!("{:?}", nostr_mls.ciphersuite as u16);
    Ok(json!({"ciphersuite": ciphersuite}).to_string())
}

/// Get the list of enabled extensions
/// Returns: JSON formatted list of extensions
pub fn get_extensions() -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let extensions: String = nostr_mls
        .extensions
        .iter()
        .map(|e| format!("{:?}", e))
        .collect::<Vec<String>>()
        .join(",");

    Ok(json!({"extensions": extensions}).to_string())
}

/// Create a key package for an event
/// Returns: JSON formatted key package information, including encoded key package and tags
pub fn create_key_package_for_event(
    public_key: String,
    relay: Option<Vec<String>>,
    client: Option<String>,
    lifetime_seconds: Option<u64>,
) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let public_key =
        PublicKey::from_str(&public_key).map_err(|e| anyhow!("Invalid public key: {}", e))?;

    let relay = relay
        .map(|relays| {
            relays
                .into_iter()
                .map(|r| RelayUrl::from_str(&r).map_err(|_| anyhow!("Invalid relay url: {}", r)))
                .collect::<Result<Vec<RelayUrl>>>()
        })
        .unwrap_or(Ok(vec![]))?;

    let (encoded_key_package, tags) = nostr_mls
        .create_key_package_for_event(&public_key, relay, client.as_deref().unwrap_or(""), lifetime_seconds)
        .map_err(|e| anyhow!("Failed to create key package: {}", e))?;

    let tags_str: Vec<String> = tags.iter().map(|tag| format!("{:?}", tag)).collect();

    Ok(json!({
        "encoded_key_package": encoded_key_package,
        "tags": tags_str
    })
    .to_string())
}

// /// Parse a key package from serialized key package
// /// Returns: JSON formatted key package information
// pub fn parse_serialized_key_package(serialized_key_package: String) -> Result<String> {
//     let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
//     let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

//     let key_package = nostr_mls
//         .parse_serialized_key_package(&serialized_key_package)
//         .map_err(|e| anyhow!("Failed to parse key package: {}", e))?;

//     Ok(json!({
//         "key_package": format!("{:?}", key_package)
//     }).to_string())
// }

/// Create a group
/// Returns: JSON formatted group information
pub fn create_group(
    group_name: String,
    group_description: String,
    group_members_serialized_key_packages: Vec<String>,
    group_members_pubkeys: Vec<String>,
    group_creator_public_key: String,
    group_admin_public_keys: Vec<String>,
    relays: Vec<String>,
) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let member_pubkeys: Result<Vec<PublicKey>> = group_members_pubkeys
        .iter()
        .map(|k| PublicKey::from_str(k).map_err(|e| anyhow!("Invalid member pubkey: {}", e)))
        .collect();
    let member_pubkeys = member_pubkeys?;

    let mut member_key_packages = Vec::new();
    for (index, serialized_key_package) in group_members_serialized_key_packages.iter().enumerate() {
        let member_pubkey = group_members_pubkeys.get(index).map(|s| s.clone());
        let key_package = nostr_mls
            .parse_serialized_key_package(serialized_key_package)
            .map_err(|e| handle_key_package_parse_error(e, member_pubkey))?;
        member_key_packages.push(key_package);
    }

    let group_admin_public_keys: Result<Vec<PublicKey>> = group_admin_public_keys
        .into_iter()
        .map(|k| PublicKey::from_str(&k).map_err(|e| anyhow!("Invalid admin pubkey: {}", e)))
        .collect();
    let group_admin_public_keys = group_admin_public_keys?;

    let group_creator_public_key = PublicKey::from_str(&group_creator_public_key)
        .map_err(|e| anyhow!("Invalid creator pubkey: {}", e))?;

    let relays: Result<Vec<RelayUrl>> = relays
        .into_iter()
        .map(|r| RelayUrl::from_str(&r).map_err(|e| anyhow!("Invalid relay url: {}", e)))
        .collect();
    let relays = relays?;

    let group_create_result = nostr_mls
        .create_group(
            group_name,
            group_description,
            &group_creator_public_key,
            &member_pubkeys,
            &member_key_packages,
            group_admin_public_keys,
            relays,
        )
        .map_err(|e| anyhow!("Failed to create group: {}", e))?;

    let mls_group = group_create_result.group;
    let group_id = mls_group.mls_group_id;

    let members: Vec<String> = match nostr_mls.get_members(&group_id) {
        Ok(members) => members.iter().map(|pk| pk.to_string()).collect(),
        Err(e) => return Err(anyhow!("Failed to get members: {}", e)),
    };

    let serialized_welcome_message = group_create_result.serialized_welcome_message;
    let nostr_group_id = mls_group.nostr_group_id;
    let name = mls_group.name;
    let description = mls_group.description;
    let admin_pubkeys = mls_group.admin_pubkeys;

    let output = json!({
        "mls_group_id": group_id,
        "members": members,
        "serialized_welcome_message": serialized_welcome_message,
        "nostr_group_data": {
            "nostr_group_id": nostr_group_id,
            "name": name,
            "description": description,
            "admin_pubkeys": admin_pubkeys,
        }
    });

    Ok(output.to_string())
}

/// Create a message for a group
/// Parameters: group_id - byte array of group ID, rumor_event_string - JSON string of the event
///             expiration - optional expiration timestamp, k - optional kind tag
/// Returns: JSON formatted message information
pub fn create_message_for_group(
    group_id: Vec<u8>,
    rumor_event_string: String,
    expiration: Option<String>,
    k: Option<String>,
) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let rumor_event = UnsignedEvent::from_json(rumor_event_string)
        .map_err(|e| anyhow!("Failed to parse event: {}", e))?;

    let group_id = GroupId::from_slice(&group_id);

    // Build additional tags
    let mut additional_tags = Vec::new();
    if let Some(exp) = expiration {
        additional_tags.push(Tag::custom(TagKind::Expiration, [exp]));
    }
    if let Some(kind_str) = k {
        // Use Tag::parse to create a custom tag with "k" as the tag name
        additional_tags.push(Tag::parse(["k", &kind_str]).map_err(|e| anyhow!("Failed to parse kind tag: {}", e))?);
    }

    let event = nostr_mls
        .create_message(
            &group_id,
            rumor_event,
            if additional_tags.is_empty() {
                None
            } else {
                Some(additional_tags)
            },
        )
        .map_err(|e| anyhow!("Failed to create message: {}", e))?;

    let event_json =
        serde_json::to_value(&event).map_err(|e| anyhow!("Failed to serialize event: {}", e))?;

    Ok(json!({
        "event": event_json
    })
    .to_string())
}

/// Create a commit message for a group
/// Parameters: group_id - byte array of group ID, serialized_commit - serialized commit
/// Returns: JSON formatted message information
pub fn create_commit_message_for_group(
    nostr_group_id: String,
    serialized_commit: Vec<u8>,
    secret_key: &[u8; 32],
) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let event = nostr_mls
        .create_commit_proposal_message(nostr_group_id, &serialized_commit, secret_key)
        .map_err(|e| anyhow!("Failed to create message: {}", e))?;

    let event_json =
        serde_json::to_value(&event).map_err(|e| anyhow!("Failed to serialize event: {}", e))?;

    Ok(json!({
        "event": event_json
    })
    .to_string())
}

/// Export group secret
/// Parameters: group_id - byte array of group ID
/// Returns: JSON formatted secret information, including secret key and epoch
pub fn export_secret(group_id: Vec<u8>) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let group_id = GroupId::from_slice(&group_id);

    let export_secret = nostr_mls
        .exporter_secret(&group_id)
        .map_err(|e| anyhow!("Failed to export secret: {}", e))?;

    Ok(json!({
        "secret": export_secret.secret,
        "epoch": export_secret.epoch
    })
    .to_string())
}

/// Process a message for a group
/// Parameters: group_id - byte array of group ID, serialized_message - serialized message
/// Returns: JSON formatted processing result
pub fn process_message_for_group(event_string: String) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let event: Event = serde_json::from_str(&event_string)
        .map_err(|e| anyhow!("Failed to deserialize event: {}", e))?;

    let result = nostr_mls.process_message(&event).map_err(|e| anyhow!("Failed to process message: {}", e))?;

    // Handle message
    let message_json = match result.message {
        Some(message) => {
            serde_json::to_value(&message)
                .map_err(|e| anyhow!("Failed to serialize message: {}", e))?
        }
        None => serde_json::Value::Null,
    };

    // Handle member_changes
    let (added_members_json, removed_members_json) = match result.member_changes {
        Some(member_changes) => {
            let added_members: Vec<String> = member_changes.added_members;
            let removed_members: Vec<String> = member_changes.removed_members;
            (
                serde_json::to_value(added_members)
                    .map_err(|e| anyhow!("Failed to serialize added_members: {}", e))?,
                serde_json::to_value(removed_members)
                    .map_err(|e| anyhow!("Failed to serialize removed_members: {}", e))?,
            )
        }
        None => (serde_json::Value::Null, serde_json::Value::Null),
    };

    Ok(json!({
        "message": message_json,
        "added_members": added_members_json,
        "removed_members": removed_members_json,
        "commit": result.commit,
        "welcome": result.welcome,
        "staged_message_bytes": result.message_bytes
    }).to_string())
}

/// Process a commit message for a specific group
/// Parameters: group_id - byte array of group ID, message_bytes - serialized message bytes
/// Returns: JSON formatted processing result
pub fn process_commit_message_for_group(group_id: Vec<u8>, message_bytes: Vec<u8>) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let group_id = GroupId::from_slice(&group_id);

    let result = nostr_mls
        .process_commit_message_for_group(&group_id, &message_bytes)
        .map_err(|e| anyhow!("Failed to process commit message: {}", e))?;

    // Handle message
    let message_json = match result.message {
        Some(message) => {
            serde_json::to_value(&message)
                .map_err(|e| anyhow!("Failed to serialize message: {}", e))?
        }
        None => serde_json::Value::Null,
    };

    // Handle member_changes
    let (added_members_json, removed_members_json) = match result.member_changes {
        Some(member_changes) => {
            let added_members: Vec<String> = member_changes.added_members;
            let removed_members: Vec<String> = member_changes.removed_members;
            (
                serde_json::to_value(added_members)
                    .map_err(|e| anyhow!("Failed to serialize added_members: {}", e))?,
                serde_json::to_value(removed_members)
                    .map_err(|e| anyhow!("Failed to serialize removed_members: {}", e))?,
            )
        }
        None => (serde_json::Value::Null, serde_json::Value::Null),
    };

    Ok(json!({
        "message": message_json,
        "added_members": added_members_json,
        "removed_members": removed_members_json,
        "commit": result.commit,
        "welcome": result.welcome,
        "staged_message_bytes": result.message_bytes
    }).to_string())
}

/// Preview a group from a welcome message without joining it
/// Parameters: wrapper_event_id - byte array of event ID, rumor_event_string - JSON string of the event
/// Returns: JSON formatted group preview information
pub fn preview_group_from_welcome(
    wrapper_event_id: Vec<u8>,
    rumor_event_string: String,
) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let rumor_event = UnsignedEvent::from_json(rumor_event_string)
        .map_err(|e| anyhow!("Failed to parse event: {}", e))?;

    let event_id =
        EventId::from_slice(&wrapper_event_id).map_err(|e| anyhow!("Invalid event ID: {}", e))?;

    let welcome_preview = nostr_mls
        .preview_welcome(&event_id, &rumor_event)
        .map_err(|e| anyhow!("Failed to process welcome: {}", e))?;

    let nostr_group_id = welcome_preview.nostr_group_data.nostr_group_id;
    let name = welcome_preview.nostr_group_data.name;
    let description = welcome_preview.nostr_group_data.description;
    let admin_pubkeys: Vec<String> = welcome_preview
        .nostr_group_data
        .admins
        .iter()
        .map(|pk| pk.to_string())
        .collect();
    let members: Vec<String> = welcome_preview.staged_welcome.members()
        .filter_map(|m| {
            let credentials = BasicCredential::try_from(m.credential).ok()?;
            let hex_bytes = credentials.identity();
            let hex_str = std::str::from_utf8(hex_bytes).ok()?;
            let public_key = PublicKey::from_hex(hex_str).ok()?;
            Some(public_key.to_string())
        })
        .collect();
    let output = json!({
        "mls_group_id": welcome_preview.staged_welcome.group_context().group_id(),
        "members": members,
        "nostr_group_data": {
            "nostr_group_id": nostr_group_id,
            "name": name,
            "description": description,
            "admin_pubkeys": admin_pubkeys,
        }
    });

    Ok(output.to_string())
}

/// Join a group from a welcome message
/// Parameters: wrapper_event_id - byte array of event ID, rumor_event_string - JSON string of the event
/// Returns: JSON formatted join result
pub fn join_group_from_welcome(
    wrapper_event_id: Vec<u8>,
    rumor_event_string: String,
) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let rumor_event = UnsignedEvent::from_json(rumor_event_string)
        .map_err(|e| anyhow!("Failed to parse event: {}", e))?;

    let event_id =
        EventId::from_slice(&wrapper_event_id).map_err(|e| anyhow!("Invalid event ID: {}", e))?;

    let welcome = nostr_mls
        .process_welcome(&event_id, &rumor_event)
        .map_err(|e| anyhow!("Failed to process welcome: {}", e))?;

    let mls_group_id = GroupId::from_slice(welcome.mls_group_id.as_slice());

    let members: Vec<String> = match nostr_mls.get_members(&mls_group_id) {
        Ok(members) => members.iter().map(|pk| pk.to_string()).collect(),
        Err(e) => return Err(anyhow!("Failed to get members: {}", e)),
    };

    let nostr_group_id = welcome.nostr_group_id;
    let name = welcome.group_name;
    let description = welcome.group_description;
    let admin_pubkeys = welcome.group_admin_pubkeys;

    let output = json!({
        "mls_group_id": mls_group_id,
        "members": members,
        "nostr_group_data": {
            "nostr_group_id": nostr_group_id,
            "name": name,
            "description": description,
            "admin_pubkeys": admin_pubkeys,
        }
    });

    Ok(output.to_string())
}

pub fn get_members(group_id: Vec<u8>) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let group_id = GroupId::from_slice(&group_id);

    let members = nostr_mls
        .get_members(&group_id)
        .map_err(|e| anyhow!("Failed to get members: {}", e))?;

    let members_str: Vec<String> = members.iter().map(|pk| pk.to_string()).collect();

    Ok(json!({
        "members": members_str
    })
    .to_string())
}

/// Get group information by group ID
/// Parameters: group_id - byte array of group ID
/// Returns: JSON formatted group information including group ID, members, and nostr group data
pub fn get_group(group_id: Vec<u8>) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let group_id = GroupId::from_slice(&group_id);

    // Get the group information
    let group = nostr_mls
        .get_group(&group_id)
        .map_err(|e| anyhow!("Failed to get group: {}", e))?
        .ok_or_else(|| anyhow!("Group not found"))?;

    // Get the members
    let members = nostr_mls
        .get_members(&group_id)
        .map_err(|e| anyhow!("Failed to get members: {}", e))?;

    let members_str: Vec<String> = members.iter().map(|pk| pk.to_string()).collect();

    let output = json!({
        "mls_group_id": group_id,
        "members": members_str,
        "nostr_group_data": {
            "nostr_group_id": group.nostr_group_id,
            "name": group.name,
            "description": group.description,
            "admin_pubkeys": group.admin_pubkeys,
        }
    });

    Ok(output.to_string())
}

/// Add members to an existing group
/// Parameters: group_id - byte array of group ID, serialized_key_packages - array of serialized key packages
/// Returns: JSON formatted result containing serialized commit and welcome messages
pub fn add_members(group_id: Vec<u8>, serialized_key_packages: Vec<String>) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let group_id = GroupId::from_slice(&group_id);

    let mut key_packages = Vec::new();
    for serialized_key_package in &serialized_key_packages {
        // For add_members, we don't have member pubkey information, so pass None
        let key_package = nostr_mls
            .parse_serialized_key_package(serialized_key_package)
            .map_err(|e| handle_key_package_parse_error(e, None))?;
        key_packages.push(key_package);
    }

    let result = nostr_mls
        .add_members(&group_id, &key_packages)
        .map_err(|e| anyhow!("Failed to add members: {}", e))?;

    Ok(json!({
        "commit_message": result.commit_message,
        "welcome_message": result.welcome_message
    })
    .to_string())
}

/// Remove members from a group
/// Parameters: group_id - byte array of group ID, member_pubkeys - array of member public keys to remove
/// Returns: JSON formatted result containing serialized commit message
pub fn remove_members(group_id: Vec<u8>, member_pubkeys: Vec<String>) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let group_id = GroupId::from_slice(&group_id);

    let result = nostr_mls
        .remove_members(&group_id, &member_pubkeys)
        .map_err(|e| anyhow!("Failed to remove members: {}", e))?;

    Ok(json!({
        "serialized_commit": result.serialized
    })
    .to_string())
}

/// Commit a proposal
/// Parameters: group_id - byte array of group ID, proposal - serialized proposal
/// Returns: JSON formatted result containing commit and welcome messages
pub fn commit_proposal(group_id: Vec<u8>, proposal: String) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let group_id = GroupId::from_slice(&group_id);

    // Parse the proposal
    let proposal: QueuedProposal = serde_json::from_str(&proposal)
        .map_err(|e| anyhow!("Failed to deserialize proposal: {}", e))?;

    let result = nostr_mls
        .commit_proposal(&group_id, proposal)
        .map_err(|e| anyhow!("Failed to commit proposal: {}", e))?;

    Ok(json!({
        "commit_message": result.commit_message,
        "welcome_message": result.welcome_message
    })
    .to_string())
}

/// Leave a group
/// Parameters: group_id - byte array of group ID
/// Returns: JSON formatted result containing serialized leave message
pub fn leave_group(group_id: Vec<u8>) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let group_id = GroupId::from_slice(&group_id);

    let result = nostr_mls
        .leave_group(&group_id)
        .map_err(|e| anyhow!("Failed to leave group: {}", e))?;

    Ok(json!({
        "serialized_leave": result.serialized
    })
    .to_string())
}

/// Get key package from storage
/// Parameters: serialized_key_package - serialized key package string
/// Returns: JSON formatted key package information
pub fn get_key_package_from_storage(serialized_key_package: String) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    // First parse the serialized key package
    // For get_key_package_from_storage, we don't have member pubkey information, so pass None
    let key_package = nostr_mls
        .parse_serialized_key_package(&serialized_key_package)
        .map_err(|e| handle_key_package_parse_error(e, None))?;

    // Then try to get it from storage
    let key_package_bundle = nostr_mls
        .get_key_package_from_storage(&key_package)
        .map_err(|e| anyhow!("Failed to get key package from storage: {}", e))?;

    // Return the result
    let result = match key_package_bundle {
        Some(bundle) => json!({
            "found": true,
            "key_package": format!("{:?}", bundle.key_package()),
        }),
        None => json!({
            "found": false,
            "key_package": null,
        })
    };

    Ok(result.to_string())
}

/// Find encoded key package from welcome event
/// Parameters: encoded_keypackages - array of encoded key package strings, wrapper_event_id - byte array of event ID, rumor_event_string - JSON string of the event
/// Returns: JSON formatted result containing the matched key package index and info if found
pub fn find_encoded_keypackage_from_welcome_event(
    encoded_keypackages: Vec<String>,
    wrapper_event_id: Vec<u8>,
    rumor_event_string: String,
) -> Result<String> {
    let mls = NOSTR_MLS
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls
        .as_ref()
        .ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let rumor_event = UnsignedEvent::from_json(rumor_event_string)
        .map_err(|e| anyhow!("Failed to parse event: {}", e))?;

    let event_id =
        EventId::from_slice(&wrapper_event_id).map_err(|e| anyhow!("Invalid event ID: {}", e))?;

    let (matched_index, keypackage_info) = nostr_mls
        .find_encoded_keypackage_from_welcome_event(&encoded_keypackages, &event_id, &rumor_event)
        .map_err(|e| anyhow!("Failed to find encoded key package: {}", e))?;

    let result = match (matched_index, keypackage_info) {
        (Some(index), Some(_info)) => json!({
            "found": true,
            "matched_index": index,
            "keypackage_info": null
        }),
        _ => json!({
            "found": false,
            "matched_index": null,
            "keypackage_info": null,
        })
    };

    Ok(result.to_string())
}
