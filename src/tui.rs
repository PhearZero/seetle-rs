use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap, Clear},
    style::{Color, Style, Modifier},
    text::{Line, Span},
    Terminal,
};
use std::{error::Error, io, sync::Arc};
use arboard::Clipboard;
use tui_logger::{TuiLoggerLevelOutput, TuiLoggerWidget};
use log::{info, error, debug};

use crate::{Seetle, Algorithm, Bindings, KeyUsage, KeyOrIdentifier, HardwareBound};
use crate::config::{load_config, save_config, is_config_existing, SeetleConfig};
use crate::init::setup_seetle;
use tokio::sync::mpsc;

enum AppEvent {
    RefreshKeys,
    ExportResult(String),
}

pub async fn run_tui() -> Result<(), Box<dyn Error>> {
    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app and run it
    let res = run_app(&mut terminal).await;

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("{:?}", err)
    }

    Ok(())
}


#[derive(PartialEq)]
enum Modal {
    None,
    Config,
    GenerateKey,
    SignData,
    VerifySignature,
    EncryptData,
    DecryptData,
    Ecdh,
    HpkeSeal,
    HpkeOpen,
    ExportKey,
    DeleteConfirmation(String),
    Error(String),
}

struct App {
    config: SeetleConfig,
    seetle: Option<Arc<dyn Seetle>>,
    keys: Vec<crate::KeyMetadata>,
    key_list_state: ListState,
    modal: Modal,
    
    // Config Dialog State
    wrapper_options: Vec<&'static str>,
    wrapper_state: ListState,
    backend_options: Vec<&'static str>,
    backend_state: ListState,
    config_active_list: usize, // 0 for wrapper, 1 for backend
    
    // Generate Key State
    gen_id: String,
    gen_alg_options: Vec<&'static str>,
    gen_alg_state: ListState,
    gen_context_options: Vec<&'static str>,
    gen_context_state: ListState,
    gen_account: String,
    gen_account_options: Vec<u32>,
    gen_index: String,
    
    // Sign State
    sign_data: String,
    sign_result: String,
    
    // Verify State
    verify_data: String,
    verify_sig: String,
    verify_result: Option<bool>,

    // Encrypt State
    encrypt_data: String,
    encrypt_result: String,

    // Decrypt State
    decrypt_data: String,
    decrypt_result: String,

    // Export State
    export_result: String,

    // ECDH State
    ecdh_peer_pub: String,
    ecdh_new_key_id: String,
    ecdh_result: String,
    ecdh_key_list_state: ListState,

    // HPKE State
    hpke_peer_pub: String,
    hpke_info: String,
    hpke_result: String,
    hpke_combined_data: String,
    hpke_key_list_state: ListState,

    clipboard: Option<Clipboard>,
}

impl App {
    async fn new() -> App {
        let config = load_config();
        let modal = if is_config_existing() {
            Modal::None
        } else {
            Modal::Config
        };

        let mut wrapper_state = ListState::default();
        wrapper_state.select(Some(0));
        let mut backend_state = ListState::default();
        backend_state.select(Some(0));
        
        let wrapper_options = vec!["keyring", "tpm", "none"];
        let backend_options = vec!["keyring", "tpm", "mock"];
        
        if let Some(idx) = wrapper_options.iter().position(|&r| r == config.storage_wrapper) {
            wrapper_state.select(Some(idx));
        }
        if let Some(idx) = backend_options.iter().position(|&r| r == config.root_backend) {
            backend_state.select(Some(idx));
        }

        let mut gen_alg_state = ListState::default();
        gen_alg_state.select(Some(0));
        let mut gen_context_state = ListState::default();
        gen_context_state.select(Some(0));

        let mut app = App {
            config,
            seetle: None,
            keys: Vec::new(),
            key_list_state: ListState::default(),
            modal,
            
            wrapper_options,
            wrapper_state,
            backend_options,
            backend_state,
            config_active_list: 0,
            
            gen_id: String::new(),
            gen_alg_options: vec!["Ed25519"],
            gen_alg_state,
            gen_context_options: vec!["Address", "Identity"],
            gen_context_state,
            gen_account: "0".to_string(),
            gen_account_options: vec![0],
            gen_index: "0".to_string(),
            
            sign_data: String::new(),
            sign_result: String::new(),
            
            verify_data: String::new(),
            verify_sig: String::new(),
            verify_result: None,

            encrypt_data: String::new(),
            encrypt_result: String::new(),

            decrypt_data: String::new(),
            decrypt_result: String::new(),

            export_result: String::new(),

            ecdh_peer_pub: String::new(),
            ecdh_new_key_id: String::new(),
            ecdh_result: String::new(),
            ecdh_key_list_state: ListState::default(),

            hpke_peer_pub: String::new(),
            hpke_info: String::new(),
            hpke_result: String::new(),
            hpke_combined_data: String::new(),
            hpke_key_list_state: ListState::default(),

            clipboard: Clipboard::new().ok(),
        };

        if app.modal == Modal::None {
            app.refresh_seetle().await;
        }

        app
    }

    async fn refresh_seetle(&mut self) {
        match setup_seetle(&self.config).await {
            Ok(s) => {
                self.seetle = Some(s);
                self.refresh_keys().await;
            }
            Err(e) => {
                error!("Failed to initialize Seetle: {}", e);
                self.modal = Modal::Error(e.to_string());
            }
        }
    }

    async fn refresh_keys(&mut self) {
        if let Some(ref s) = self.seetle {
            match s.list_keys().await {
                Ok(mut ids) => {
                    let master_id = "seetle-master-seed";
                    if !ids.contains(&master_id.to_string()) {
                        ids.push(master_id.to_string());
                    }
                    ids.sort();
                    let mut keys = Vec::new();
                    for id in ids {
                        match s.get_key_metadata(id.clone()).await {
                            Ok(m) => keys.push(m),
                            Err(e) => {
                                if id == master_id {
                                    // Synthesize metadata for the master seed if it's missing from storage
                                    // This allows the UI to show it deterministically.
                                    keys.push(crate::KeyMetadata {
                                        identifier: id,
                                        algorithm: "MasterSeed (Hardware-backed)".to_string(),
                                        usages: vec![crate::KeyUsage::DeriveBits],
                                        hardware_bound: crate::HardwareBound::Yes,
                                        extractable: true,
                                        ..Default::default()
                                    });
                                } else {
                                    error!("Failed to get metadata for {}: {}", id, e);
                                    // Push minimal metadata if it fails
                                    keys.push(crate::KeyMetadata {
                                        identifier: id,
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                    self.keys = keys;
                    self.update_xhd_defaults();
                    if self.key_list_state.selected().is_none() && !self.keys.is_empty() {
                        self.key_list_state.select(Some(0));
                    }
                }
                Err(e) => error!("Failed to list keys: {}", e),
            }
        }
    }

    fn update_xhd_defaults(&mut self) {
        let mut accounts = vec![0];
        for k in &self.keys {
            if let Some(acc) = k.account {
                if !accounts.contains(&acc) {
                    accounts.push(acc);
                }
            }
        }
        accounts.sort();
        self.gen_account_options = accounts;

        if self.gen_context_state.selected().is_none() {
            self.gen_context_state.select(Some(0));
        }
        self.update_suggested_index();
    }
    
    fn update_suggested_index(&mut self) {
        let context = self.gen_context_options[self.gen_context_state.selected().unwrap_or(0)];
        let account: u32 = self.gen_account.parse().unwrap_or(0);
        
        let mut max_index = -1i32;
        for k in &self.keys {
            if k.context.as_deref() == Some(context) && k.account == Some(account) {
                if let Some(idx) = k.index {
                    if idx as i32 > max_index {
                        max_index = idx as i32;
                    }
                }
            }
        }
        self.gen_index = (max_index + 1).to_string();
    }

    fn next_key(&mut self) {
        if self.keys.is_empty() { return; }
        let i = match self.key_list_state.selected() {
            Some(i) => if i >= self.keys.len() - 1 { 0 } else { i + 1 },
            None => 0,
        };
        self.key_list_state.select(Some(i));
    }

    fn previous_key(&mut self) {
        if self.keys.is_empty() { return; }
        let i = match self.key_list_state.selected() {
            Some(i) => if i == 0 { self.keys.len() - 1 } else { i - 1 },
            None => 0,
        };
        self.key_list_state.select(Some(i));
    }
    
    // Helper for config lists
    fn next_config(&mut self) {
        if self.config_active_list == 0 {
            let i = match self.wrapper_state.selected() {
                Some(i) => if i >= self.wrapper_options.len() - 1 { 0 } else { i + 1 },
                None => 0,
            };
            self.wrapper_state.select(Some(i));
        } else {
            let i = match self.backend_state.selected() {
                Some(i) => if i >= self.backend_options.len() - 1 { 0 } else { i + 1 },
                None => 0,
            };
            self.backend_state.select(Some(i));
        }
    }

    fn previous_config(&mut self) {
        if self.config_active_list == 0 {
            let i = match self.wrapper_state.selected() {
                Some(i) => if i == 0 { self.wrapper_options.len() - 1 } else { i - 1 },
                None => 0,
            };
            self.wrapper_state.select(Some(i));
        } else {
            let i = match self.backend_state.selected() {
                Some(i) => if i == 0 { self.backend_options.len() - 1 } else { i - 1 },
                None => 0,
            };
            self.backend_state.select(Some(i));
        }
    }
}

async fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>) -> Result<(), Box<dyn Error>> {
    let mut app = App::new().await;
    let (tx, mut rx) = mpsc::channel::<AppEvent>(10);
    debug!("TUI started");

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if app.modal != Modal::None {
                    match app.modal {
                        Modal::Config => {
                            match key.code {
                                KeyCode::Char('q') => return Ok(()),
                                KeyCode::Down => app.next_config(),
                                KeyCode::Up => app.previous_config(),
                                KeyCode::Tab => app.config_active_list = (app.config_active_list + 1) % 2,
                                KeyCode::Enter => {
                                    let wrapper = app.wrapper_options[app.wrapper_state.selected().unwrap_or(0)];
                                    let backend = app.backend_options[app.backend_state.selected().unwrap_or(0)];
                                    app.config.storage_wrapper = wrapper.to_string();
                                    app.config.root_backend = backend.to_string();
                                    if let Err(e) = save_config(&app.config) {
                                        error!("Failed to save config: {}", e);
                                    } else {
                                        debug!("Config saved");
                                        app.modal = Modal::None;
                                        app.seetle = None; // Trigger re-initialization
                                    }
                                }
                                _ => {}
                            }
                            if app.modal == Modal::None {
                                // Initialization after config save
                                // Need to do it outside the draw closure but we are in run_app
                            }
                        }
                        Modal::GenerateKey => {
                            match key.code {
                                KeyCode::Esc => app.modal = Modal::None,
                                KeyCode::Char(c) => {
                                    if app.config_active_list == 0 {
                                        app.gen_id.push(c);
                                    } else if app.config_active_list == 3 {
                                        if c.is_ascii_digit() {
                                            app.gen_account.push(c);
                                            app.update_suggested_index();
                                        }
                                    } else if app.config_active_list == 4 {
                                        if c.is_ascii_digit() {
                                            app.gen_index.push(c);
                                        }
                                    }
                                }
                                KeyCode::Backspace => {
                                    if app.config_active_list == 0 {
                                        app.gen_id.pop();
                                    } else if app.config_active_list == 3 {
                                        app.gen_account.pop();
                                        app.update_suggested_index();
                                    } else if app.config_active_list == 4 {
                                        app.gen_index.pop();
                                    }
                                }
                                KeyCode::Tab => {
                                    app.config_active_list = (app.config_active_list + 1) % 5;
                                }
                                KeyCode::Up => {
                                    match app.config_active_list {
                                        1 => {
                                            let i = match app.gen_alg_state.selected() {
                                                Some(i) => if i == 0 { app.gen_alg_options.len() - 1 } else { i - 1 },
                                                None => 0,
                                            };
                                            app.gen_alg_state.select(Some(i));
                                        }
                                        2 => {
                                            let i = match app.gen_context_state.selected() {
                                                Some(i) => if i == 0 { app.gen_context_options.len() - 1 } else { i - 1 },
                                                None => 0,
                                            };
                                            app.gen_context_state.select(Some(i));
                                            app.update_suggested_index();
                                        }
                                        3 => {
                                            let current_acc: u32 = app.gen_account.parse().unwrap_or(0);
                                            let i = match app.gen_account_options.iter().position(|&a| a == current_acc) {
                                                Some(i) => if i == 0 { app.gen_account_options.len() - 1 } else { i - 1 },
                                                None => 0,
                                            };
                                            app.gen_account = app.gen_account_options[i].to_string();
                                            app.update_suggested_index();
                                        }
                                        _ => {}
                                    }
                                }
                                KeyCode::Down => {
                                    match app.config_active_list {
                                        1 => {
                                            let i = match app.gen_alg_state.selected() {
                                                Some(i) => if i >= app.gen_alg_options.len() - 1 { 0 } else { i + 1 },
                                                None => 0,
                                            };
                                            app.gen_alg_state.select(Some(i));
                                        }
                                        2 => {
                                            let i = match app.gen_context_state.selected() {
                                                Some(i) => if i >= app.gen_context_options.len() - 1 { 0 } else { i + 1 },
                                                None => 0,
                                            };
                                            app.gen_context_state.select(Some(i));
                                            app.update_suggested_index();
                                        }
                                        3 => {
                                            let current_acc: u32 = app.gen_account.parse().unwrap_or(0);
                                            let i = match app.gen_account_options.iter().position(|&a| a == current_acc) {
                                                Some(i) => if i >= app.gen_account_options.len() - 1 { 0 } else { i + 1 },
                                                None => 0,
                                            };
                                            app.gen_account = app.gen_account_options[i].to_string();
                                            app.update_suggested_index();
                                        }
                                        _ => {}
                                    }
                                }
                                KeyCode::Enter => {
                                    if !app.gen_id.is_empty() {
                                        let identifier = app.gen_id.clone();
                                        let alg_str = app.gen_alg_options[app.gen_alg_state.selected().unwrap_or(0)];
                                        
                                        let context = app.gen_context_options[app.gen_context_state.selected().unwrap_or(0)];
                                        let account: u32 = app.gen_account.parse().unwrap_or(0);
                                        let index: u32 = app.gen_index.parse().unwrap_or(0);

                                        let algorithm = match alg_str {
                                            "Ed25519" => Algorithm::Ed25519 { name: format!("XHD:{}:{}:{}:Peikert", context, account, index) },
                                            "ECDSA P-256" => Algorithm::Ecdsa { name: "ECDSA".into(), named_curve: "P-256".into(), hash: Some("SHA-256".into()) },
                                            "RSA-PSS 2048" => Algorithm::RsaPss { 
                                                name: "RSA-PSS".into(), 
                                                modulus_length: 2048, 
                                                public_exponent: vec![0x01, 0x00, 0x01], 
                                                hash: "SHA-256".into(),
                                                salt_length: 32,
                                            },
                                            _ => Algorithm::Ed25519 { name: "Ed25519".into() },
                                        };
                                        
                                        info!("Generating key: {} with algorithm: {}", identifier, alg_str);
                                        let seetle = app.seetle.clone().unwrap();
                                        app.modal = Modal::None;
                                        let tx_clone = tx.clone();
                                        tokio::spawn(async move {
                                            match seetle.generate_key(
                                                algorithm,
                                                false,
                                                Some(Bindings {
                                                    identifier,
                                                    hardware_bound: HardwareBound::Yes,
                                                    ..Default::default()
                                                }),
                                                vec![KeyUsage::Sign, KeyUsage::Verify]
                                            ).await {
                                                Ok(_) => {
                                                    info!("Key generated successfully");
                                                    let _ = tx_clone.send(AppEvent::RefreshKeys).await;
                                                }
                                                Err(e) => error!("Failed to generate key: {}", e),
                                            }
                                        });
                                    }
                                }
                                _ => {}
                            }
                        }
                        Modal::SignData => {
                            match key.code {
                                KeyCode::Esc => app.modal = Modal::None,
                                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                    if !app.sign_result.is_empty() {
                                        let result = app.sign_result.clone();
                                        if let Some(ref mut clipboard) = app.clipboard {
                                            if let Err(e) = clipboard.set_text(result) {
                                                error!("Failed to copy to clipboard: {}", e);
                                            } else {
                                                info!("Signature copied to clipboard");
                                            }
                                        } else {
                                            // Try to re-initialize if it failed earlier
                                            match Clipboard::new() {
                                                Ok(mut cb) => {
                                                    if let Err(e) = cb.set_text(result) {
                                                        error!("Failed to copy to clipboard: {}", e);
                                                    } else {
                                                        info!("Signature copied to clipboard");
                                                    }
                                                    app.clipboard = Some(cb);
                                                }
                                                Err(e) => error!("Clipboard not available: {}", e),
                                            }
                                        }
                                    }
                                }
                                KeyCode::Char(c) => app.sign_data.push(c),
                                KeyCode::Backspace => { app.sign_data.pop(); }
                                KeyCode::Enter => {
                                    if let Some(idx) = app.key_list_state.selected() {
                                        let identifier = app.keys[idx].identifier.clone();
                                        let data = app.sign_data.clone();
                                        let seetle = app.seetle.clone().unwrap();
                                        info!("Signing data with key: {}", identifier);
                                        match seetle.sign(
                                            Algorithm::Ed25519 { name: "Ed25519".into() },
                                            KeyOrIdentifier::Identifier(identifier),
                                            data.into_bytes()
                                        ).await {
                                            Ok(sig) => {
                                                info!("Signed successfully");
                                                app.sign_result = hex::encode(sig);
                                            }
                                            Err(e) => {
                                                error!("Failed to sign: {}", e);
                                                app.sign_result = format!("Error: {}", e);
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Modal::VerifySignature => {
                            match key.code {
                                KeyCode::Esc => app.modal = Modal::None,
                                KeyCode::Char(c) => {
                                    if app.verify_result.is_none() { // If not showing result
                                        if app.config_active_list == 0 { // Reusing config_active_list as field selector
                                            app.verify_data.push(c);
                                        } else {
                                            app.verify_sig.push(c);
                                        }
                                    }
                                }
                                KeyCode::Backspace => {
                                    if app.verify_result.is_none() {
                                        if app.config_active_list == 0 {
                                            app.verify_data.pop();
                                        } else {
                                            app.verify_sig.pop();
                                        }
                                    }
                                }
                                KeyCode::Tab => {
                                    if app.verify_result.is_none() {
                                        app.config_active_list = (app.config_active_list + 1) % 2;
                                    }
                                }
                                KeyCode::Enter => {
                                    if let Some(_verified) = app.verify_result {
                                        app.modal = Modal::None;
                                        app.verify_result = None;
                                    } else if let Some(idx) = app.key_list_state.selected() {
                                        let identifier = app.keys[idx].identifier.clone();
                                        let data = app.verify_data.clone();
                                        let sig_hex = app.verify_sig.clone();
                                        let seetle = app.seetle.clone().unwrap();
                                        
                                        match hex::decode(sig_hex) {
                                            Ok(sig) => {
                                                info!("Verifying signature with key: {}", identifier);
                                                match seetle.verify(
                                                    Algorithm::Ed25519 { name: "Ed25519".into() },
                                                    KeyOrIdentifier::Identifier(identifier),
                                                    sig,
                                                    data.into_bytes()
                                                ).await {
                                                    Ok(v) => {
                                                        app.verify_result = Some(v);
                                                        info!("Verification result: {}", v);
                                                    }
                                                    Err(e) => error!("Failed to verify: {}", e),
                                                }
                                            }
                                            Err(e) => error!("Invalid signature hex: {}", e),
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Modal::EncryptData => {
                            match key.code {
                                KeyCode::Esc => app.modal = Modal::None,
                                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                    if !app.encrypt_result.is_empty() {
                                        let result = app.encrypt_result.clone();
                                        if let Some(ref mut clipboard) = app.clipboard {
                                            if let Err(e) = clipboard.set_text(result) {
                                                error!("Failed to copy to clipboard: {}", e);
                                            } else {
                                                info!("Encrypted data copied to clipboard");
                                            }
                                        } else {
                                            match Clipboard::new() {
                                                Ok(mut cb) => {
                                                    if let Err(e) = cb.set_text(result) {
                                                        error!("Failed to copy to clipboard: {}", e);
                                                    } else {
                                                        info!("Encrypted data copied to clipboard");
                                                    }
                                                    app.clipboard = Some(cb);
                                                }
                                                Err(e) => error!("Clipboard not available: {}", e),
                                            }
                                        }
                                    }
                                }
                                KeyCode::Char(c) => app.encrypt_data.push(c),
                                KeyCode::Backspace => { app.encrypt_data.pop(); }
                                KeyCode::Enter => {
                                    if let Some(idx) = app.key_list_state.selected() {
                                        let identifier = app.keys[idx].identifier.clone();
                                        let data = app.encrypt_data.clone();
                                        let seetle = app.seetle.clone().unwrap();
                                        info!("Encrypting data with key: {}", identifier);
                                        match seetle.encrypt(
                                            Algorithm::Generic { name: "AesGcm".into() },
                                            KeyOrIdentifier::Identifier(identifier),
                                            data.into_bytes()
                                        ).await {
                                            Ok(enc) => {
                                                info!("Encrypted successfully");
                                                app.encrypt_result = hex::encode(enc);
                                            }
                                            Err(e) => {
                                                error!("Failed to encrypt: {}", e);
                                                app.encrypt_result = format!("Error: {}", e);
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Modal::DecryptData => {
                            match key.code {
                                KeyCode::Esc => app.modal = Modal::None,
                                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                    if !app.decrypt_result.is_empty() {
                                        let result = app.decrypt_result.clone();
                                        if let Some(ref mut clipboard) = app.clipboard {
                                            if let Err(e) = clipboard.set_text(result) {
                                                error!("Failed to copy to clipboard: {}", e);
                                            } else {
                                                info!("Decrypted data copied to clipboard");
                                            }
                                        } else {
                                            match Clipboard::new() {
                                                Ok(mut cb) => {
                                                    if let Err(e) = cb.set_text(result) {
                                                        error!("Failed to copy to clipboard: {}", e);
                                                    } else {
                                                        info!("Decrypted data copied to clipboard");
                                                    }
                                                    app.clipboard = Some(cb);
                                                }
                                                Err(e) => error!("Clipboard not available: {}", e),
                                            }
                                        }
                                    }
                                }
                                KeyCode::Char(c) => app.decrypt_data.push(c),
                                KeyCode::Backspace => { app.decrypt_data.pop(); }
                                KeyCode::Enter => {
                                    if let Some(idx) = app.key_list_state.selected() {
                                        let identifier = app.keys[idx].identifier.clone();
                                        let data_hex = app.decrypt_data.clone();
                                        let seetle = app.seetle.clone().unwrap();
                                        
                                        match hex::decode(data_hex) {
                                            Ok(data) => {
                                                info!("Decrypting data with key: {}", identifier);
                                                match seetle.decrypt(
                                                    Algorithm::Generic { name: "AesGcm".into() },
                                                    KeyOrIdentifier::Identifier(identifier),
                                                    data
                                                ).await {
                                                    Ok(dec) => {
                                                        info!("Decrypted successfully");
                                                        app.decrypt_result = String::from_utf8_lossy(&dec).to_string();
                                                    }
                                                    Err(e) => {
                                                        error!("Failed to decrypt: {}", e);
                                                        app.decrypt_result = format!("Error: {}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => error!("Invalid encrypted hex: {}", e),
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Modal::Ecdh => {
                            match key.code {
                                KeyCode::Esc => app.modal = Modal::None,
                                KeyCode::Tab => app.config_active_list = (app.config_active_list + 1) % 3,
                                KeyCode::Up => if app.config_active_list == 2 {
                                    let i = match app.ecdh_key_list_state.selected() {
                                        Some(i) => if i == 0 { app.keys.len() - 1 } else { i - 1 },
                                        None => 0,
                                    };
                                    app.ecdh_key_list_state.select(Some(i));
                                },
                                KeyCode::Down => if app.config_active_list == 2 {
                                    let i = match app.ecdh_key_list_state.selected() {
                                        Some(i) => if i >= app.keys.len() - 1 { 0 } else { i + 1 },
                                        None => 0,
                                    };
                                    app.ecdh_key_list_state.select(Some(i));
                                },
                                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                    if !app.ecdh_result.is_empty() {
                                        let result = app.ecdh_result.clone();
                                        if let Some(ref mut clipboard) = app.clipboard {
                                            if let Err(e) = clipboard.set_text(result) {
                                                error!("Failed to copy to clipboard: {}", e);
                                            } else {
                                                info!("Shared secret copied to clipboard");
                                            }
                                        } else {
                                            match Clipboard::new() {
                                                Ok(mut cb) => {
                                                    if let Err(e) = cb.set_text(result) {
                                                        error!("Failed to copy to clipboard: {}", e);
                                                    } else {
                                                        info!("Shared secret copied to clipboard");
                                                    }
                                                    app.clipboard = Some(cb);
                                                }
                                                Err(e) => error!("Clipboard not available: {}", e),
                                            }
                                        }
                                    }
                                }
                                KeyCode::Char(c) => match app.config_active_list {
                                    0 => app.ecdh_peer_pub.push(c),
                                    1 => app.ecdh_new_key_id.push(c),
                                    _ => {}
                                },
                                KeyCode::Backspace => match app.config_active_list {
                                    0 => { app.ecdh_peer_pub.pop(); }
                                    1 => { app.ecdh_new_key_id.pop(); }
                                    _ => {}
                                },
                                KeyCode::Enter => {
                                    if app.config_active_list == 2 {
                                        // Select key from list
                                        if let Some(idx) = app.ecdh_key_list_state.selected() {
                                            if let Some(pk) = &app.keys[idx].public_key {
                                                app.ecdh_peer_pub = hex::encode(pk);
                                                app.config_active_list = 0;
                                            }
                                        }
                                    } else if let Some(idx) = app.key_list_state.selected() {
                                        let identifier = app.keys[idx].identifier.clone();
                                        let peer_pub_hex = app.ecdh_peer_pub.clone();
                                        let new_key_id = app.ecdh_new_key_id.clone();
                                        let seetle = app.seetle.clone().unwrap();
                                        
                                        match hex::decode(peer_pub_hex) {
                                            Ok(peer_pub) => {
                                                info!("Deriving shared secret via ECDH with key: {}", identifier);
                                                let alg_name = if !new_key_id.is_empty() {
                                                    format!("SAVE_KEY:{}", new_key_id)
                                                } else {
                                                    "X25519".to_string()
                                                };
                                                match seetle.derive_bits(
                                                    Algorithm::Ecdh { name: alg_name, public_key: peer_pub },
                                                    KeyOrIdentifier::Identifier(identifier),
                                                    256
                                                ).await {
                                                    Ok(secret) => {
                                                        info!("Shared secret derived successfully");
                                                        if !new_key_id.is_empty() {
                                                            info!("New keypair created from secret: {}", new_key_id);
                                                            let _ = tx.send(AppEvent::RefreshKeys).await;
                                                        }
                                                        app.ecdh_result = hex::encode(secret);
                                                    }
                                                    Err(e) => {
                                                        error!("Failed to derive shared secret: {}", e);
                                                        app.ecdh_result = format!("Error: {}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => error!("Invalid peer public key hex: {}", e),
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Modal::HpkeSeal => {
                            match key.code {
                                KeyCode::Esc => app.modal = Modal::None,
                                KeyCode::Tab => app.config_active_list = (app.config_active_list + 1) % 4,
                                KeyCode::Up if app.config_active_list == 3 => {
                                    let i = match app.hpke_key_list_state.selected() {
                                        Some(i) => if i == 0 { app.keys.len() - 1 } else { i - 1 },
                                        None => 0,
                                    };
                                    app.hpke_key_list_state.select(Some(i));
                                }
                                KeyCode::Down if app.config_active_list == 3 => {
                                    let i = match app.hpke_key_list_state.selected() {
                                        Some(i) => if i >= app.keys.len() - 1 { 0 } else { i + 1 },
                                        None => 0,
                                    };
                                    app.hpke_key_list_state.select(Some(i));
                                }
                                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                    if !app.hpke_result.is_empty() {
                                        let result = app.hpke_result.clone();
                                        if let Some(ref mut clipboard) = app.clipboard {
                                            if let Err(e) = clipboard.set_text(result) {
                                                error!("Failed to copy to clipboard: {}", e);
                                            } else {
                                                info!("Result copied to clipboard");
                                            }
                                        } else {
                                            match Clipboard::new() {
                                                Ok(mut cb) => {
                                                    if let Err(e) = cb.set_text(result) {
                                                        error!("Failed to copy to clipboard: {}", e);
                                                    } else {
                                                        info!("Result copied to clipboard");
                                                    }
                                                    app.clipboard = Some(cb);
                                                }
                                                Err(e) => error!("Clipboard not available: {}", e),
                                            }
                                        }
                                    }
                                }
                                KeyCode::Char(c) => match app.config_active_list {
                                    0 => app.hpke_peer_pub.push(c),
                                    1 => app.hpke_info.push(c),
                                    2 => app.encrypt_data.push(c),
                                    _ => {}
                                },
                                KeyCode::Backspace => match app.config_active_list {
                                    0 => { app.hpke_peer_pub.pop(); }
                                    1 => { app.hpke_info.pop(); }
                                    2 => { app.encrypt_data.pop(); }
                                    _ => {}
                                },
                                KeyCode::Enter => {
                                    if app.config_active_list == 3 {
                                        if let Some(idx) = app.hpke_key_list_state.selected() {
                                            if let Some(pk) = &app.keys[idx].public_key {
                                                app.hpke_peer_pub = hex::encode(pk);
                                                app.config_active_list = 0;
                                            }
                                        }
                                    } else {
                                        let peer_pub_hex = app.hpke_peer_pub.clone();
                                        let info_str = app.hpke_info.clone();
                                        let data = app.encrypt_data.clone();
                                        let seetle = app.seetle.clone().unwrap();

                                        match hex::decode(peer_pub_hex) {
                                            Ok(peer_pub) => {
                                                info!("HPKE sealing data");
                                                match seetle.encrypt(
                                                    Algorithm::Hpke {
                                                        name: "DHKEM_X25519_HKDF_SHA256".into(),
                                                        public_key: Some(peer_pub.clone()),
                                                        info: Some(info_str.clone().into_bytes()),
                                                    },
                                                    KeyOrIdentifier::Identifier("ignored".into()),
                                                    data.into_bytes()
                                                ).await {
                                                    Ok(res) => {
                                                        info!("HPKE sealed successfully");
                                                        app.hpke_result = hex::encode(res);
                                                    }
                                                    Err(e) => {
                                                        error!("HPKE seal failed: {}", e);
                                                        app.hpke_result = format!("Error: {}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => error!("Invalid peer public key hex: {}", e),
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Modal::HpkeOpen => {
                            match key.code {
                                KeyCode::Esc => app.modal = Modal::None,
                                KeyCode::Tab => app.config_active_list = (app.config_active_list + 1) % 2,
                                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                    if !app.hpke_result.is_empty() {
                                        let result = app.hpke_result.clone();
                                        if let Some(ref mut clipboard) = app.clipboard {
                                            if let Err(e) = clipboard.set_text(result) {
                                                error!("Failed to copy to clipboard: {}", e);
                                            } else {
                                                info!("Result copied to clipboard");
                                            }
                                        } else {
                                            match Clipboard::new() {
                                                Ok(mut cb) => {
                                                    if let Err(e) = cb.set_text(result) {
                                                        error!("Failed to copy to clipboard: {}", e);
                                                    } else {
                                                        info!("Result copied to clipboard");
                                                    }
                                                    app.clipboard = Some(cb);
                                                }
                                                Err(e) => error!("Clipboard not available: {}", e),
                                            }
                                        }
                                    }
                                }
                                KeyCode::Char(c) => match app.config_active_list {
                                    0 => app.hpke_combined_data.push(c),
                                    1 => app.hpke_info.push(c),
                                    _ => {}
                                },
                                KeyCode::Backspace => match app.config_active_list {
                                    0 => { app.hpke_combined_data.pop(); }
                                    1 => { app.hpke_info.pop(); }
                                    _ => {}
                                },
                                KeyCode::Enter => {
                                    if let Some(idx) = app.key_list_state.selected() {
                                        let identifier = app.keys[idx].identifier.clone();
                                        let combined_hex = app.hpke_combined_data.clone();
                                        let info_str = app.hpke_info.clone();
                                        let seetle = app.seetle.clone().unwrap();

                                        match hex::decode(combined_hex) {
                                            Ok(combined_data) => {
                                                info!("HPKE opening data with key: {}", identifier);
                                                match seetle.decrypt(
                                                    Algorithm::Hpke {
                                                        name: "DHKEM_X25519_HKDF_SHA256".into(),
                                                        public_key: None,
                                                        info: Some(info_str.into_bytes()),
                                                    },
                                                    KeyOrIdentifier::Identifier(identifier),
                                                    combined_data
                                                ).await {
                                                    Ok(res) => {
                                                        info!("HPKE opened successfully");
                                                        app.hpke_result = String::from_utf8_lossy(&res).to_string();
                                                    }
                                                    Err(e) => {
                                                        error!("HPKE open failed: {}", e);
                                                        app.hpke_result = format!("Error: {}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => error!("Invalid hex data: {}", e),
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Modal::ExportKey => {
                            match key.code {
                                KeyCode::Esc | KeyCode::Enter => app.modal = Modal::None,
                                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                    if !app.export_result.is_empty() {
                                        let result = app.export_result.clone();
                                        if let Some(ref mut clipboard) = app.clipboard {
                                            if let Err(e) = clipboard.set_text(result) {
                                                error!("Failed to copy to clipboard: {}", e);
                                            } else {
                                                info!("Exported key material copied to clipboard");
                                            }
                                        } else {
                                            match Clipboard::new() {
                                                Ok(mut cb) => {
                                                    let _ = cb.set_text(result);
                                                    app.clipboard = Some(cb);
                                                    info!("Exported key material copied to clipboard");
                                                }
                                                Err(e) => error!("Clipboard not available: {}", e),
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Modal::Error(_) => {
                            if key.code == KeyCode::Enter || key.code == KeyCode::Esc {
                                app.modal = Modal::None;
                            }
                        }
                        Modal::DeleteConfirmation(ref identifier) => {
                            match key.code {
                                KeyCode::Enter => {
                                    let seetle = app.seetle.clone().unwrap();
                                    let id = identifier.clone();
                                    info!("Deleting key: {}", id);
                                    match seetle.delete_key(id.clone()).await {
                                        Ok(_) => {
                                            info!("Key deleted successfully");
                                            if id == "seetle-master-seed" {
                                                app.refresh_seetle().await;
                                            } else {
                                                app.refresh_keys().await;
                                            }
                                        }
                                        Err(e) => error!("Failed to delete key: {}", e),
                                    }
                                    app.modal = Modal::None;
                                }
                                KeyCode::Esc | KeyCode::Char('n') => {
                                    app.modal = Modal::None;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Down => app.next_key(),
                        KeyCode::Up => app.previous_key(),
                        KeyCode::Char('g') => {
                            app.gen_id.clear();
                            app.gen_account = "0".to_string();
                            app.gen_context_state.select(Some(0));
                            app.update_xhd_defaults();
                            app.modal = Modal::GenerateKey;
                            app.config_active_list = 0;
                        }
                        KeyCode::Char('s') => {
                            if app.key_list_state.selected().is_some() {
                                app.sign_data.clear();
                                app.sign_result.clear();
                                app.modal = Modal::SignData;
                            }
                        }
                        KeyCode::Char('v') => {
                            if app.key_list_state.selected().is_some() {
                                app.verify_data.clear();
                                app.verify_sig.clear();
                                app.verify_result = None;
                                app.config_active_list = 0;
                                app.modal = Modal::VerifySignature;
                            }
                        }
                        KeyCode::Char('e') => {
                            if app.key_list_state.selected().is_some() {
                                app.encrypt_data.clear();
                                app.encrypt_result.clear();
                                app.modal = Modal::EncryptData;
                            }
                        }
                        KeyCode::Char('x') => {
                            if app.key_list_state.selected().is_some() {
                                app.decrypt_data.clear();
                                app.decrypt_result.clear();
                                app.modal = Modal::DecryptData;
                            }
                        }
                        KeyCode::Char('X') => {
                            if let Some(idx) = app.key_list_state.selected() {
                                let identifier = app.keys[idx].identifier.clone();
                                if app.keys[idx].extractable {
                                    app.export_result.clear();
                                    app.modal = Modal::ExportKey;
                                    let seetle = app.seetle.clone().unwrap();
                                    let tx_clone = tx.clone();
                                    tokio::spawn(async move {
                                        info!("Exporting key: {}", identifier);
                                        match seetle.export_key("raw".into(), KeyOrIdentifier::Identifier(identifier)).await {
                                            Ok(key_data) => {
                                                info!("Key exported successfully");
                                                let _ = tx_clone.send(AppEvent::ExportResult(hex::encode(key_data))).await;
                                            }
                                            Err(e) => error!("Failed to export key: {}", e),
                                        }
                                    });
                                } else {
                                    error!("Key is not extractable");
                                }
                            }
                        }
                        KeyCode::Char('a') => {
                            if app.key_list_state.selected().is_some() {
                                app.ecdh_peer_pub.clear();
                                app.ecdh_new_key_id.clear();
                                app.ecdh_result.clear();
                                app.ecdh_key_list_state.select(Some(0));
                                app.modal = Modal::Ecdh;
                                app.config_active_list = 0;
                            }
                        }
                        KeyCode::Char('h') => {
                            if app.key_list_state.selected().is_some() {
                                app.hpke_peer_pub.clear();
                                app.hpke_info.clear();
                                app.hpke_result.clear();
                                app.hpke_key_list_state.select(Some(0));
                                app.modal = Modal::HpkeSeal;
                                app.config_active_list = 0;
                            }
                        }
                        KeyCode::Char('o') => {
                            if app.key_list_state.selected().is_some() {
                                app.hpke_info.clear();
                                app.hpke_result.clear();
                                app.hpke_combined_data.clear();
                                app.modal = Modal::HpkeOpen;
                                app.config_active_list = 0;
                            }
                        }
                        KeyCode::Char('r') => {
                            app.refresh_keys().await;
                        }
                        KeyCode::Char('d') => {
                            if let Some(idx) = app.key_list_state.selected() {
                                let identifier = app.keys[idx].identifier.clone();
                                app.modal = Modal::DeleteConfirmation(identifier);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        
        // Process background events
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::RefreshKeys => app.refresh_keys().await,
                AppEvent::ExportResult(res) => app.export_result = res,
            }
        }
        
        // Background refresh of keys if needed
        if app.modal == Modal::None && app.seetle.is_none() {
            app.refresh_seetle().await;
        }
    }
}

fn ui(f: &mut ratatui::Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),      // Header
            Constraint::Length(12),       // Main area (Keys + Details) - 10 lines of content + borders
            Constraint::Min(0),          // Logs
            Constraint::Length(3),       // Footer
        ].as_ref())
        .split(f.area());

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" SEETLE ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(format!("[Backend: {}]", app.config.root_backend.to_uppercase()), Style::default().fg(Color::Yellow)),
        Span::raw(" "),
        Span::styled(format!("[Wrapper: {}]", app.config.storage_wrapper.to_uppercase()), Style::default().fg(Color::Green)),
        Span::raw(" "),
        Span::styled("Secure Hardware-Backed Storage", Style::default().fg(Color::Cyan).add_modifier(Modifier::ITALIC)),
    ]));
    f.render_widget(header, chunks[0]);

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[1]);

    // Key List
    let items: Vec<ListItem> = app.keys.iter().map(|k| {
        let pub_key_str = k.public_key.as_ref().map(|pk| hex::encode(pk)).unwrap_or_else(|| "SEED (N/A)".to_string());
        ListItem::new(vec![
            Line::from(vec![
                Span::styled(&k.identifier, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                if !k.extractable { 
                    Span::styled(" [Non-Extractable]", Style::default().fg(Color::Red).add_modifier(Modifier::ITALIC)) 
                } else { 
                    Span::raw("") 
                }
            ]),
            Line::from(vec![Span::styled(format!("  {}", pub_key_str), Style::default().fg(Color::DarkGray))]),
        ])
    }).collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(Span::styled(" Keys ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan))))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD).bg(Color::Rgb(50, 50, 50)))
        .highlight_symbol("> ");
    f.render_stateful_widget(list, main_chunks[0], &mut app.key_list_state);

    // Key Details
    let details_block = Block::default().borders(Borders::ALL).title(Span::styled(" Key Details ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta)));
    let details = if let Some(i) = app.key_list_state.selected() {
        if let Some(k) = app.keys.get(i) {
            let mut text = vec![
                Line::from(vec![Span::styled("Identifier: ", Style::default().fg(Color::Gray)), Span::styled(&k.identifier, Style::default().fg(Color::White).add_modifier(Modifier::BOLD))]),
                Line::from(vec![Span::styled("Algorithm:  ", Style::default().fg(Color::Gray)), Span::styled(&k.algorithm, Style::default().fg(Color::Cyan))]),
                Line::from(vec![
                    Span::styled("HW Bound:   ", Style::default().fg(Color::Gray)), 
                    match k.hardware_bound {
                        HardwareBound::Yes => Span::styled("Yes", Style::default().fg(Color::Green)),
                        HardwareBound::Partial => Span::styled("Partial", Style::default().fg(Color::Yellow)),
                        HardwareBound::No => Span::styled("No", Style::default().fg(Color::Red)),
                    }
                ]),
                Line::from(vec![
                    Span::styled("Extractable:", Style::default().fg(Color::Gray)), 
                    if k.extractable { 
                        Span::styled("Yes", Style::default().fg(Color::Green)) 
                    } else { 
                        Span::styled("No", Style::default().fg(Color::Red)) 
                    }
                ]),
            ];

            if let Some(ctx) = &k.context {
                let color = if ctx == "ECDH" { Color::Yellow } else { Color::Blue };
                text.push(Line::from(vec![Span::styled("Context:    ", Style::default().fg(Color::Gray)), Span::styled(ctx, Style::default().fg(color))]));
            }
            if let Some(source) = &k.source_key_identifier {
                text.push(Line::from(vec![Span::styled("Source Key: ", Style::default().fg(Color::Gray)), Span::styled(source, Style::default().fg(Color::Cyan))]));
            }
            if let Some(acc) = k.account {
                text.push(Line::from(vec![Span::styled("Account:    ", Style::default().fg(Color::Gray)), Span::styled(acc.to_string(), Style::default().fg(Color::Blue))]));
            }
            if let Some(idx) = k.index {
                text.push(Line::from(vec![Span::styled("Index:      ", Style::default().fg(Color::Gray)), Span::styled(idx.to_string(), Style::default().fg(Color::Blue))]));
            }
            if let Some(der) = &k.derivation {
                text.push(Line::from(vec![Span::styled("Derivation: ", Style::default().fg(Color::Gray)), Span::styled(der, Style::default().fg(Color::Blue))]));
            }

            Paragraph::new(text).block(details_block).wrap(Wrap { trim: true })
        } else {
            Paragraph::new("No key selected").block(details_block)
        }
    } else {
        Paragraph::new("No key selected").block(details_block)
    };
    f.render_widget(details, main_chunks[1]);

    // Logs
    let tui_sm = TuiLoggerWidget::default()
        .output_separator('|')
        .output_timestamp(Some("%H:%M:%S".to_string()))
        .output_level(Some(TuiLoggerLevelOutput::Long))
        .output_target(false)
        .output_file(false)
        .output_line(false)
        .block(Block::default().borders(Borders::ALL).title(Span::styled(" Logs ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Green))));
    f.render_widget(tui_sm, chunks[2]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("g", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": New Key | "),
        Span::styled("s", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": Sign Data | "),
        Span::styled("v", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": Verify Sig | "),
        Span::styled("e", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": Encrypt | "),
        Span::styled("x", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": Decrypt | "),
        Span::styled("a", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": ECDH | "),
        Span::styled("h", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": HPKE Seal | "),
        Span::styled("o", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": HPKE Open | "),
        Span::styled("X", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": Export | "),
        Span::styled("d", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": Delete Key | "),
        Span::styled("r", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": Refresh List | "),
        Span::styled("q", Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)), Span::raw(": Quit"),
    ]))
    .block(Block::default().borders(Borders::ALL).title(Span::styled(" Commands ", Style::default().fg(Color::Yellow))).border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(footer, chunks[3]);

    // Modals
    match &app.modal {
        Modal::Config => {
            let area = centered_rect(60, 80, f.area());
            f.render_widget(Clear, area);
            let block = Block::default().borders(Borders::ALL).title(Span::styled(" Initial Configuration ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan)));
            f.render_widget(block, area);
            
            let config_chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Length(7), Constraint::Length(7), Constraint::Min(1)].as_ref())
                .split(area);
            
            // Wrapper
            let wrapper_items: Vec<ListItem> = app.wrapper_options.iter().map(|&i| ListItem::new(i)).collect();
            let mut wrapper_block = Block::default().borders(Borders::ALL).title("Storage Wrapper");
            if app.config_active_list == 0 { wrapper_block = wrapper_block.border_style(Style::default().fg(Color::Yellow)); }
            let wrapper_list = List::new(wrapper_items).block(wrapper_block).highlight_symbol("> ");
            f.render_stateful_widget(wrapper_list, config_chunks[0], &mut app.wrapper_state);

            // Backend
            let backend_items: Vec<ListItem> = app.backend_options.iter().map(|&i| ListItem::new(i)).collect();
            let mut backend_block = Block::default().borders(Borders::ALL).title("Root Backend");
            if app.config_active_list == 1 { backend_block = backend_block.border_style(Style::default().fg(Color::Yellow)); }
            let backend_list = List::new(backend_items).block(backend_block).highlight_symbol("> ");
            f.render_stateful_widget(backend_list, config_chunks[1], &mut app.backend_state);
            
            let help = Paragraph::new("Use Arrow keys to select, Tab to switch, Enter to Save and Continue")
                .wrap(Wrap { trim: true });
            f.render_widget(help, config_chunks[2]);
        }
        Modal::DeleteConfirmation(identifier) => {
            let area = centered_rect(40, 20, f.area());
            f.render_widget(Clear, area);
            let block = Block::default().borders(Borders::ALL).title("Confirm Delete").border_style(Style::default().fg(Color::Red));
            f.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Min(1), Constraint::Length(1)].as_ref())
                .split(area);

            let text = vec![
                Line::from(vec![Span::raw("Are you sure you want to delete key: ")]),
                Line::from(vec![Span::styled(identifier, Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow))]),
            ];
            f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), chunks[0]);
            
            let help = Paragraph::new("Enter to Confirm, Esc/n to Cancel")
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Center);
            f.render_widget(help, chunks[1]);
        }
        Modal::GenerateKey => {
            let area = centered_rect(60, 80, f.area());
            f.render_widget(Clear, area);
            let block = Block::default().borders(Borders::ALL).title(Span::styled(" Generate Key ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan)));
            f.render_widget(block, area);
            
            let gen_chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3), // Identifier
                    Constraint::Length(5), // Algorithm
                    Constraint::Length(5), // Context & Account
                    Constraint::Length(3), // Index
                    Constraint::Min(1)     // Help
                ].as_ref())
                .split(area);
            
            let mut id_block = Block::default().borders(Borders::ALL).title("Identifier");
            if app.config_active_list == 0 { id_block = id_block.border_style(Style::default().fg(Color::Yellow)); }
            let id_input = Paragraph::new(app.gen_id.as_str()).block(id_block);
            f.render_widget(id_input, gen_chunks[0]);
            
            let mut alg_block = Block::default().borders(Borders::ALL).title("Algorithm");
            if app.config_active_list == 1 { alg_block = alg_block.border_style(Style::default().fg(Color::Yellow)); }
            let alg_items: Vec<ListItem> = app.gen_alg_options.iter().map(|&i| ListItem::new(i)).collect();
            let alg_list = List::new(alg_items)
                .block(alg_block)
                .highlight_symbol("> ");
            f.render_stateful_widget(alg_list, gen_chunks[1], &mut app.gen_alg_state);

            let ctx_acc_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(gen_chunks[2]);

            let mut ctx_block = Block::default().borders(Borders::ALL).title("Context");
            if app.config_active_list == 2 { ctx_block = ctx_block.border_style(Style::default().fg(Color::Yellow)); }
            let ctx_items: Vec<ListItem> = app.gen_context_options.iter().map(|&i| ListItem::new(i)).collect();
            let ctx_list = List::new(ctx_items).block(ctx_block).highlight_symbol("> ");
            f.render_stateful_widget(ctx_list, ctx_acc_chunks[0], &mut app.gen_context_state);

            let mut acc_block = Block::default().borders(Borders::ALL).title("Account (Number)");
            if app.config_active_list == 3 { acc_block = acc_block.border_style(Style::default().fg(Color::Yellow)); }
            let acc_input = Paragraph::new(app.gen_account.as_str()).block(acc_block);
            f.render_widget(acc_input, ctx_acc_chunks[1]);

            let mut idx_block = Block::default().borders(Borders::ALL).title("Index");
            if app.config_active_list == 4 { idx_block = idx_block.border_style(Style::default().fg(Color::Yellow)); }
            let idx_display = Paragraph::new(app.gen_index.as_str()).block(idx_block);
            f.render_widget(idx_display, gen_chunks[3]);
            
            let help = Paragraph::new("Tab: Switch field, Arrows: Select, Enter: Generate, Esc: Cancel");
            f.render_widget(help, gen_chunks[4]);
        }
        Modal::SignData => {
            let area = centered_rect(60, 70, f.area());
            f.render_widget(Clear, area);
            let mut block = Block::default().borders(Borders::ALL).title(Span::styled(" Sign Data ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta)));
            if let Some(idx) = app.key_list_state.selected() {
                block = block.title_bottom(format!(" Using Key: {} ", app.keys[idx].identifier));
            }
            f.render_widget(block, area);
            
            let sign_chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Length(3), Constraint::Min(3), Constraint::Length(1)].as_ref())
                .split(area);
                
            let data_input = Paragraph::new(app.sign_data.as_str())
                .block(Block::default().borders(Borders::ALL).title("Data to sign"));
            f.render_widget(data_input, sign_chunks[0]);
            
            let result_output = Paragraph::new(app.sign_result.as_str())
                .block(Block::default().borders(Borders::ALL).title("Signature (Hex)"))
                .wrap(Wrap { trim: true });
            f.render_widget(result_output, sign_chunks[1]);
            
            let help = Paragraph::new("Enter: Sign, Ctrl-C: Copy Result, Esc: Close");
            f.render_widget(help, sign_chunks[2]);
        }
        Modal::VerifySignature => {
            let area = centered_rect(60, 85, f.area());
            f.render_widget(Clear, area);
            let mut block = Block::default().borders(Borders::ALL).title(Span::styled(" Verify Signature ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta)));
            if let Some(idx) = app.key_list_state.selected() {
                block = block.title_bottom(format!(" Using Key: {} ", app.keys[idx].identifier));
            }
            f.render_widget(block, area);
            
            let verify_chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Min(3), Constraint::Length(1)].as_ref())
                .split(area);
                
            let mut data_block = Block::default().borders(Borders::ALL).title("Data");
            if app.config_active_list == 0 { data_block = data_block.border_style(Style::default().fg(Color::Yellow)); }
            let data_input = Paragraph::new(app.verify_data.as_str()).block(data_block);
            f.render_widget(data_input, verify_chunks[0]);
            
            let mut sig_block = Block::default().borders(Borders::ALL).title("Signature (Hex)");
            if app.config_active_list == 1 { sig_block = sig_block.border_style(Style::default().fg(Color::Yellow)); }
            let sig_input = Paragraph::new(app.verify_sig.as_str()).block(sig_block).wrap(Wrap { trim: true });
            f.render_widget(sig_input, verify_chunks[1]);
            
            let result_text = match app.verify_result {
                Some(true) => "VALID",
                Some(false) => "INVALID",
                None => "Not verified yet",
            };
            let result_style = match app.verify_result {
                Some(true) => Style::default().fg(Color::Green),
                Some(false) => Style::default().fg(Color::Red),
                None => Style::default(),
            };
            let result_output = Paragraph::new(result_text)
                .block(Block::default().borders(Borders::ALL).title("Result"))
                .style(result_style);
            f.render_widget(result_output, verify_chunks[2]);
            
            let help = Paragraph::new("Tab: Switch field, Enter: Verify/Close, Esc: Cancel");
            f.render_widget(help, verify_chunks[3]);
        }
        Modal::EncryptData => {
            let area = centered_rect(60, 70, f.area());
            f.render_widget(Clear, area);
            let mut block = Block::default().borders(Borders::ALL).title(Span::styled(" Encrypt Data ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta)));
            if let Some(idx) = app.key_list_state.selected() {
                block = block.title_bottom(format!(" Using Key: {} ", app.keys[idx].identifier));
            }
            f.render_widget(block, area);
            
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Length(3), Constraint::Min(3), Constraint::Length(1)].as_ref())
                .split(area);
                
            let data_input = Paragraph::new(app.encrypt_data.as_str())
                .block(Block::default().borders(Borders::ALL).title("Data to encrypt"));
            f.render_widget(data_input, chunks[0]);
            
            let result_output = Paragraph::new(app.encrypt_result.as_str())
                .block(Block::default().borders(Borders::ALL).title("Encrypted (Hex)"))
                .wrap(Wrap { trim: true });
            f.render_widget(result_output, chunks[1]);
            
            let help = Paragraph::new("Enter: Encrypt, Ctrl-C: Copy Result, Esc: Close");
            f.render_widget(help, chunks[2]);
        }
        Modal::DecryptData => {
            let area = centered_rect(60, 70, f.area());
            f.render_widget(Clear, area);
            let mut block = Block::default().borders(Borders::ALL).title(Span::styled(" Decrypt Data ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta)));
            if let Some(idx) = app.key_list_state.selected() {
                block = block.title_bottom(format!(" Using Key: {} ", app.keys[idx].identifier));
            }
            f.render_widget(block, area);
            
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Length(3), Constraint::Min(3), Constraint::Length(1)].as_ref())
                .split(area);
                
            let data_input = Paragraph::new(app.decrypt_data.as_str())
                .block(Block::default().borders(Borders::ALL).title("Encrypted Data (Hex)"));
            f.render_widget(data_input, chunks[0]);
            
            let result_output = Paragraph::new(app.decrypt_result.as_str())
                .block(Block::default().borders(Borders::ALL).title("Decrypted Data"))
                .wrap(Wrap { trim: true });
            f.render_widget(result_output, chunks[1]);
            
            let help = Paragraph::new("Enter: Decrypt, Ctrl-C: Copy Result, Esc: Close");
            f.render_widget(help, chunks[2]);
        }
        Modal::Ecdh => {
            let area = centered_rect(60, 95, f.area());
            f.render_widget(Clear, area);
            let mut block = Block::default().borders(Borders::ALL).title(Span::styled(" ECDH Key Agreement ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta)));
            if let Some(idx) = app.key_list_state.selected() {
                block = block.title_bottom(format!(" Using Key: {} ", app.keys[idx].identifier));
            }
            f.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3), // Peer Pub
                    Constraint::Length(3), // New Key ID
                    Constraint::Min(3),    // Result
                    Constraint::Length(5), // Key List
                    Constraint::Length(1)  // Help
                ].as_ref())
                .split(area);

            let mut peer_pub_block = Block::default().borders(Borders::ALL).title("Peer Public Key (Hex)");
            if app.config_active_list == 0 { peer_pub_block = peer_pub_block.border_style(Style::default().fg(Color::Yellow)); }
            let peer_pub_input = Paragraph::new(app.ecdh_peer_pub.as_str()).block(peer_pub_block).wrap(Wrap { trim: true });
            f.render_widget(peer_pub_input, chunks[0]);

            let mut new_key_id_block = Block::default().borders(Borders::ALL).title("New Key Identifier (Optional, save as Key)");
            if app.config_active_list == 1 { new_key_id_block = new_key_id_block.border_style(Style::default().fg(Color::Yellow)); }
            let new_key_id_input = Paragraph::new(app.ecdh_new_key_id.as_str()).block(new_key_id_block);
            f.render_widget(new_key_id_input, chunks[1]);

            let result_output = Paragraph::new(app.ecdh_result.as_str())
                .block(Block::default().borders(Borders::ALL).title("Shared Secret (Hex)"))
                .wrap(Wrap { trim: true });
            f.render_widget(result_output, chunks[2]);

            let mut keys_block = Block::default().borders(Borders::ALL).title("Select Peer Key from List");
            if app.config_active_list == 2 { keys_block = keys_block.border_style(Style::default().fg(Color::Yellow)); }
            let items: Vec<ListItem> = app.keys.iter().map(|k| ListItem::new(k.identifier.as_str())).collect();
            let keys_list = List::new(items).block(keys_block).highlight_symbol("> ");
            f.render_stateful_widget(keys_list, chunks[3], &mut app.ecdh_key_list_state);

            let help = Paragraph::new("Tab: Switch, Arrows: Select Key, Enter: Agree/Select, Ctrl-C: Copy Result, Esc: Close");
            f.render_widget(help, chunks[4]);
        }
        Modal::HpkeSeal => {
            let area = centered_rect(60, 80, f.area());
            f.render_widget(Clear, area);
            let block = Block::default().borders(Borders::ALL).title(Span::styled(" HPKE Seal (Encrypt) ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta)));
            f.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3), // Peer Pub
                    Constraint::Length(3), // Info
                    Constraint::Length(3), // Data
                    Constraint::Min(3),    // Result
                    Constraint::Length(5), // Key List
                    Constraint::Length(1)  // Help
                ].as_ref())
                .split(area);

            let mut peer_pub_block = Block::default().borders(Borders::ALL).title("Recipient Public Key (Hex)");
            if app.config_active_list == 0 { peer_pub_block = peer_pub_block.border_style(Style::default().fg(Color::Yellow)); }
            f.render_widget(Paragraph::new(app.hpke_peer_pub.as_str()).block(peer_pub_block), chunks[0]);

            let mut info_block = Block::default().borders(Borders::ALL).title("Info (Optional)");
            if app.config_active_list == 1 { info_block = info_block.border_style(Style::default().fg(Color::Yellow)); }
            f.render_widget(Paragraph::new(app.hpke_info.as_str()).block(info_block), chunks[1]);

            let mut data_block = Block::default().borders(Borders::ALL).title("Plaintext Data");
            if app.config_active_list == 2 { data_block = data_block.border_style(Style::default().fg(Color::Yellow)); }
            f.render_widget(Paragraph::new(app.encrypt_data.as_str()).block(data_block), chunks[2]);

            let result_output = Paragraph::new(app.hpke_result.as_str())
                .block(Block::default().borders(Borders::ALL).title("Combined (Encapped Key + Ciphertext) (Hex)"))
                .wrap(Wrap { trim: true });
            f.render_widget(result_output, chunks[3]);

            let mut keys_block = Block::default().borders(Borders::ALL).title("Select Recipient Key from List");
            if app.config_active_list == 3 { keys_block = keys_block.border_style(Style::default().fg(Color::Yellow)); }
            let items: Vec<ListItem> = app.keys.iter().map(|k| ListItem::new(k.identifier.as_str())).collect();
            let keys_list = List::new(items).block(keys_block).highlight_symbol("> ");
            f.render_stateful_widget(keys_list, chunks[4], &mut app.hpke_key_list_state);

            let help = Paragraph::new("Tab: Switch, Arrows: Select Key, Enter: Seal/Select, Ctrl-C: Copy Result, Esc: Close");
            f.render_widget(help, chunks[5]);
        }
        Modal::HpkeOpen => {
            let area = centered_rect(60, 60, f.area());
            f.render_widget(Clear, area);
            let mut block = Block::default().borders(Borders::ALL).title(Span::styled(" HPKE Open (Decrypt) ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta)));
            if let Some(idx) = app.key_list_state.selected() {
                block = block.title_bottom(format!(" Using Key: {} ", app.keys[idx].identifier));
            }
            f.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3), // Combined Data
                    Constraint::Length(3), // Info
                    Constraint::Min(3),    // Result
                    Constraint::Length(1)  // Help
                ].as_ref())
                .split(area);

            let mut combined_block = Block::default().borders(Borders::ALL).title("Combined Data (Encapped Key + Ciphertext) (Hex)");
            if app.config_active_list == 0 { combined_block = combined_block.border_style(Style::default().fg(Color::Yellow)); }
            f.render_widget(Paragraph::new(app.hpke_combined_data.as_str()).block(combined_block).wrap(Wrap { trim: true }), chunks[0]);

            let mut info_block = Block::default().borders(Borders::ALL).title("Info");
            if app.config_active_list == 1 { info_block = info_block.border_style(Style::default().fg(Color::Yellow)); }
            f.render_widget(Paragraph::new(app.hpke_info.as_str()).block(info_block), chunks[1]);

            let result_output = Paragraph::new(app.hpke_result.as_str())
                .block(Block::default().borders(Borders::ALL).title("Decrypted Plaintext"))
                .wrap(Wrap { trim: true });
            f.render_widget(result_output, chunks[2]);

            let help = Paragraph::new("Tab: Switch, Enter: Open, Ctrl-C: Copy Result, Esc: Close");
            f.render_widget(help, chunks[3]);
        }
        Modal::ExportKey => {
            let area = centered_rect(60, 40, f.area());
            f.render_widget(Clear, area);
            let mut block = Block::default().borders(Borders::ALL).title(Span::styled(" Export Key ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta)));
            if let Some(idx) = app.key_list_state.selected() {
                block = block.title_bottom(format!(" Exporting: {} ", app.keys[idx].identifier));
            }
            f.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Min(3), Constraint::Length(1)].as_ref())
                .split(area);

            let result_output = Paragraph::new(app.export_result.as_str())
                .block(Block::default().borders(Borders::ALL).title("Exported Key Material (Hex)"))
                .wrap(Wrap { trim: true });
            f.render_widget(result_output, chunks[0]);

            let help = Paragraph::new("Ctrl-C: Copy, Enter/Esc: Close");
            f.render_widget(help, chunks[1]);
        }
        Modal::Error(msg) => {
            let area = centered_rect(40, 20, f.area());
            f.render_widget(Clear, area);
            let block = Block::default().borders(Borders::ALL).title("Error").border_style(Style::default().fg(Color::Red));
            let p = Paragraph::new(msg.as_str()).block(block).wrap(Wrap { trim: true });
            f.render_widget(p, area);
        }
        _ => {}
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ].as_ref())
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ].as_ref())
        .split(popup_layout[1])[1]
}
