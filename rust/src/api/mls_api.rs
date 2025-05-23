use anyhow::{Result, anyhow};
use lazy_static::lazy_static;
use nostr_mls::prelude::*;
use nostr_mls::NostrMls;
use nostr_mls_sqlite_storage::NostrMlsSqliteStorage;
use serde_json::{json};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

lazy_static! {
    static ref NOSTR_MLS: Mutex<Option<NostrMls<NostrMlsSqliteStorage>>> = Mutex::new(None);
}

/// Initialize the NostrMls instance
/// Returns: JSON {"status": "success"} on success, or error message on failure
pub fn init_nostr_mls(path: String, identity: Option<String>) -> Result<String> {
    let mut mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;

    if let Some(old_mls) = mls.take() {
        drop(old_mls);
    }
    
    let db_path =
        PathBuf::from(path).join(identity.as_deref().unwrap_or("default").to_owned() + "-mls.db");

    let nostr_mls = NostrMls::new(NostrMlsSqliteStorage::new(db_path)
        .map_err(|e| anyhow!("Failed to initialize storage: {}", e))?);
    
    *mls = Some(nostr_mls);
    
    Ok(json!({"status": "success"}).to_string())
}

/// Get the current ciphersuite
/// Returns: JSON formatted ciphersuite information
pub fn get_ciphersuite() -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let ciphersuite = format!("{:?}", nostr_mls.ciphersuite as u16);
    Ok(json!({"ciphersuite": ciphersuite}).to_string())
}

/// Get the list of enabled extensions
/// Returns: JSON formatted list of extensions
pub fn get_extensions() -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

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
pub fn create_key_package_for_event(public_key: String, relay: Option<Vec<String>>) -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let public_key = PublicKey::from_str(&public_key)
        .map_err(|e| anyhow!("Invalid public key: {}", e))?;
        
    let relay = relay
        .map(|relays| {
            relays
                .into_iter()
                .map(|r| RelayUrl::from_str(&r).map_err(|_| anyhow!("Invalid relay url: {}", r)))
                .collect::<Result<Vec<RelayUrl>>>()
        })
        .unwrap_or(Ok(vec![]))?;
        
    let (encoded_key_package, tags) = nostr_mls
        .create_key_package_for_event(&public_key, relay)
        .map_err(|e| anyhow!("Failed to create key package: {}", e))?;

    let tags_str: Vec<String> = tags
        .iter()
        .map(|tag| format!("{:?}", tag))
        .collect();

    Ok(json!({
        "encoded_key_package": encoded_key_package,
        "tags": tags_str
    }).to_string())
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
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let member_pubkeys: Result<Vec<PublicKey>> = group_members_pubkeys
        .into_iter()
        .map(|k| PublicKey::from_str(&k).map_err(|e| anyhow!("Invalid member pubkey: {}", e)))
        .collect();
    let member_pubkeys = member_pubkeys?;

    let mut member_key_packages = Vec::new();
    for serialized_key_package in &group_members_serialized_key_packages {
        let key_package = nostr_mls
            .parse_serialized_key_package(&serialized_key_package)
            .map_err(|e| anyhow!("Failed to parse key package: {}", e))?;
        member_key_packages.push(key_package);
    }

    let group_admin_public_keys: Result<Vec<PublicKey>> = group_admin_public_keys
        .into_iter()
        .map(|k| PublicKey::from_str(&k).map_err(|e| anyhow!("Invalid admin pubkey: {}", e)))
        .collect();
    let group_admin_public_keys = group_admin_public_keys?;

    let group_creator_public_key =
        PublicKey::from_str(&group_creator_public_key)
            .map_err(|e| anyhow!("Invalid creator pubkey: {}", e))?;

    let relays: Result<Vec<RelayUrl>> = relays
        .into_iter()
        .map(|r| RelayUrl::from_str(&r).map_err(|e| anyhow!("Invalid relay url: {}", e)))
        .collect();
    let relays = relays?;

    let group_create_result = nostr_mls.create_group(
        group_name,
        group_description,
        &group_creator_public_key,
        &member_pubkeys,
        &member_key_packages,
        group_admin_public_keys,
        relays,
    ).map_err(|e| anyhow!("Failed to create group: {}", e))?;

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
/// Returns: JSON formatted message information
pub fn create_message_for_group(group_id: Vec<u8>, rumor_event_string: String) -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;
    
    let rumor_event = UnsignedEvent::from_json(rumor_event_string)
        .map_err(|e| anyhow!("Failed to parse event: {}", e))?;
    
    let group_id = GroupId::from_slice(&group_id);
        
    let event = nostr_mls.create_message(&group_id, rumor_event)
        .map_err(|e| anyhow!("Failed to create message: {}", e))?;
        
    let event_json = serde_json::to_value(&event)
        .map_err(|e| anyhow!("Failed to serialize event: {}", e))?;
    
    Ok(json!({
        "event": event_json
    }).to_string())
}

/// Export group secret
/// Parameters: group_id - byte array of group ID
/// Returns: JSON formatted secret information, including secret key and epoch
pub fn export_secret(group_id: Vec<u8>) -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;
    
    let group_id = GroupId::from_slice(&group_id);

    let export_secret = nostr_mls.exporter_secret(&group_id)
        .map_err(|e| anyhow!("Failed to export secret: {}", e))?;
        
    let secret_hex = ::hex::encode(export_secret.secret);
    let epoch = export_secret.epoch;

    Ok(json!({
        "secret": secret_hex,
        "epoch": epoch
    }).to_string())
}

/// Process a message for a group
/// Parameters: group_id - byte array of group ID, serialized_message - serialized message
/// Returns: JSON formatted processing result
pub fn process_message_for_group(event_string: String) -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;
    
    let event: Event = serde_json::from_str(&event_string)
        .map_err(|e| anyhow!("Failed to deserialize event: {}", e))?;

    let event = nostr_mls.process_message(&event)
        .map_err(|e| anyhow!("Failed to process message: {}", e))?
        .ok_or_else(|| anyhow!("No event returned"))?;
    
    let event_json = serde_json::to_value(&event)
        .map_err(|e| anyhow!("Failed to serialize event: {}", e))?;
    
    Ok(json!({
        "event": event_json
    }).to_string())
}

/// Preview a group from a welcome message without joining it
/// Parameters: wrapper_event_id - byte array of event ID, rumor_event_string - JSON string of the event
/// Returns: JSON formatted group preview information
pub fn preview_group_from_welcome(
    wrapper_event_id: Vec<u8>,
    rumor_event_string: String,
) -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let rumor_event = UnsignedEvent::from_json(rumor_event_string)
        .map_err(|e| anyhow!("Failed to parse event: {}", e))?;

    let event_id = EventId::from_slice(&wrapper_event_id)
        .map_err(|e| anyhow!("Invalid event ID: {}", e))?;

    let welcome_preview = nostr_mls.preview_welcome(&event_id, &rumor_event)
        .map_err(|e| anyhow!("Failed to process welcome: {}", e))?;

    let nostr_group_id = welcome_preview.nostr_group_data.nostr_group_id;
    let name = welcome_preview.nostr_group_data.name;
    let description = welcome_preview.nostr_group_data.description;
    let admin_pubkeys: Vec<String> = welcome_preview.nostr_group_data.admins.iter().map(|pk| pk.to_string()).collect();

    let output = json!({
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
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let rumor_event = UnsignedEvent::from_json(rumor_event_string)
        .map_err(|e| anyhow!("Failed to parse event: {}", e))?;

    let event_id = EventId::from_slice(&wrapper_event_id)
        .map_err(|e| anyhow!("Invalid event ID: {}", e))?;

    nostr_mls.process_welcome(&event_id, &rumor_event)
        .map_err(|e| anyhow!("Failed to process welcome: {}", e))?;

    let pending_welcomes = nostr_mls.get_pending_welcomes()
        .map_err(|e| anyhow!("Failed to get pending welcomes: {}", e))?;
    let welcome = pending_welcomes.first().unwrap();
    nostr_mls.accept_welcome(welcome)
        .map_err(|e| anyhow!("Failed to accept welcome: {}", e))?;

    let mls_group = nostr_mls.get_groups()?.first().unwrap().clone();
    let mls_group_id = GroupId::from_slice(mls_group.mls_group_id.as_slice());

    let members: Vec<String> = match nostr_mls.get_members(&mls_group_id) {
        Ok(members) => members.iter().map(|pk| pk.to_string()).collect(),
        Err(e) => return Err(anyhow!("Failed to get members: {}", e)),
    };

    let nostr_group_id = mls_group.nostr_group_id;
    let name = mls_group.name;
    let description = mls_group.description;
    let admin_pubkeys = mls_group.admin_pubkeys;

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
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;

    let group_id = GroupId::from_slice(&group_id);

    let members = nostr_mls.get_members(&group_id)
        .map_err(|e| anyhow!("Failed to get members: {}", e))?;

    let members_str: Vec<String> = members.iter().map(|pk| pk.to_string()).collect();

    Ok(json!({
        "members": members_str
    }).to_string())
}

/// Add members to an existing group
/// Parameters: group_id - byte array of group ID, serialized_key_packages - array of serialized key packages
/// Returns: JSON formatted result containing serialized commit and welcome messages
pub fn add_members(group_id: Vec<u8>, serialized_key_packages: Vec<String>) -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;
    
    let group_id = GroupId::from_slice(&group_id);
    
    let mut key_packages = Vec::new();
    for serialized_key_package in &serialized_key_packages {
        let key_package = nostr_mls
            .parse_serialized_key_package(&serialized_key_package)
            .map_err(|e| anyhow!("Failed to parse key package: {}", e))?;
        key_packages.push(key_package);
    }
    
    let result = nostr_mls.add_members(&group_id, &key_packages)
        .map_err(|e| anyhow!("Failed to add members: {}", e))?;
    
    Ok(json!({
        "commit_message": result.commit_message,
        "welcome_message": result.welcome_message
    }).to_string())
}

/// Remove members from a group
/// Parameters: group_id - byte array of group ID, member_indices - array of member indices to remove
/// Returns: JSON formatted result containing serialized commit message
pub fn remove_members(group_id: Vec<u8>, member_indices: Vec<u32>) -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;
    
    let group_id = GroupId::from_slice(&group_id);
    
    let result = nostr_mls.remove_members(&group_id, &member_indices)
        .map_err(|e| anyhow!("Failed to remove members: {}", e))?;
    
    Ok(json!({
        "serialized_commit": result.serialized
    }).to_string())
}

/// Commit a proposal
/// Parameters: group_id - byte array of group ID, proposal - serialized proposal
/// Returns: JSON formatted result containing commit and welcome messages
pub fn commit_proposal(group_id: Vec<u8>, proposal: String) -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;
    
    let group_id = GroupId::from_slice(&group_id);
    
    // Parse the proposal
    let proposal: QueuedProposal = serde_json::from_str(&proposal)
        .map_err(|e| anyhow!("Failed to deserialize proposal: {}", e))?;
    
    let result = nostr_mls.commit_proposal(&group_id, proposal)
        .map_err(|e| anyhow!("Failed to commit proposal: {}", e))?;
    
    Ok(json!({
        "commit_message": result.commit_message,
        "welcome_message": result.welcome_message
    }).to_string())
}

/// Leave a group
/// Parameters: group_id - byte array of group ID
/// Returns: JSON formatted result containing serialized leave message
pub fn leave_group(group_id: Vec<u8>) -> Result<String> {
    let mls = NOSTR_MLS.lock().map_err(|_| anyhow!("Failed to acquire NOSTR_MLS lock"))?;
    let nostr_mls = mls.as_ref().ok_or_else(|| anyhow!("NostrMls is not initialized"))?;
    
    let group_id = GroupId::from_slice(&group_id);
    
    let result = nostr_mls.leave_group(&group_id)
        .map_err(|e| anyhow!("Failed to leave group: {}", e))?;
    
    Ok(json!({
        "serialized_leave": result.serialized
    }).to_string())
}
