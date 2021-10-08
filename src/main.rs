use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Client, Request, Response, Server,
};
use hyper_rustls::HttpsConnector;
use log::{debug, error, info, trace};
use nadylib::{
    models::{Channel, ChannelType},
    packets::{
        GroupMessagePacket, IncomingPacket, LoginCharlistPacket, LoginSeedPacket,
        LoginSelectPacket, PacketType,
    },
    AOSocket, SocketConfig,
};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpStream,
    time::{sleep, Duration},
};

use std::{
    collections::HashMap,
    convert::Infallible,
    env,
    error::Error,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, RwLock},
    time::Instant,
};

type HotSites = Arc<RwLock<HashMap<(u32, u8), (TowerSite, Instant)>>>;

#[derive(Deserialize, Serialize)]
struct TowerSite {
    playfield_id: u32,
    playfield_long_name: String,
    playfield_short_name: String,
    site_number: u8,
    ql: u16,
    min_ql: u16,
    max_ql: u16,
    x_coord: u32,
    y_coord: u32,
    org_name: String,
    org_id: u32,
    faction: String,
    site_name: String,
    close_time: usize,
    created_at: usize,
    enabled: u8,
}

#[derive(Deserialize)]
struct SearchResult {
    count: usize,
    results: Vec<TowerSite>,
}

async fn wait_server_ready(addr: &str) {
    while TcpStream::connect(addr).await.is_err() {
        sleep(Duration::from_secs(10)).await;
    }
}

async fn cleanup_task(hot_sites: HotSites) {
    loop {
        sleep(Duration::from_secs(60)).await;
        let mut sites = hot_sites.write().expect("rwlock poisoned");
        let before = sites.len();

        if before == 0 {
            continue;
        }

        sites
            .retain(|_, (_, expiry)| (Instant::now() - *expiry) < Duration::from_secs(60 * 60 * 2));
        let after = sites.len();
        info!("Set {} sites as no longer hot", before - after);
    }
}

async fn chat_client(hot_sites: HotSites) -> nadylib::Result<()> {
    let org_regex = RegexBuilder::new(
        r"^The (Clan|Neutral|Omni) organization (.+) just entered a state of war! (.+) attacked the (Clan|Neutral|Omni) organization (.+)'s tower in (.+) at location \((\d+),(\d+)\)\.$",
    ).case_insensitive(true).build().unwrap();

    let client: Client<_, Body> = Client::builder().build(HttpsConnector::with_webpki_roots());

    loop {
        info!("Waiting for chat server to be available");
        wait_server_ready("chat.d1.funcom.com:7105").await;

        let mut socket =
            AOSocket::connect("chat.d1.funcom.com:7105", SocketConfig::default()).await?;

        while let Ok(packet) = socket.read_raw_packet().await {
            debug!("Received {:?} packet", packet.0);
            trace!("Packet body: {:?}", packet.1);

            match packet.0 {
                PacketType::LoginOk => info!("Logged in to chat servers"),
                PacketType::LoginError => {
                    error!("Failed to login to chat servers");
                    return Ok(());
                }
                PacketType::LoginSeed => {
                    let login_seed_packet = LoginSeedPacket::load(&packet.1)?;
                    socket
                        .login(
                            &env::var("USERNAME").expect("USERNAME not set"),
                            &env::var("PASSWORD").expect("PASSWORD not set"),
                            &login_seed_packet.login_seed,
                        )
                        .await?;
                }
                PacketType::LoginCharlist => {
                    let login_charlist_packet = LoginCharlistPacket::load(&packet.1)?;
                    let character = login_charlist_packet
                        .characters
                        .iter()
                        .find(|c| c.name == env::var("CHARACTER").expect("CHARACTER not set"))
                        .expect("Character is not on this account");
                    let pack = LoginSelectPacket {
                        character_id: character.id,
                    };
                    socket.send(pack).await?;
                }
                PacketType::GroupMessage => {
                    let group_message_packet = GroupMessagePacket::load(&packet.1)?;
                    if matches!(&group_message_packet.message.channel, Channel::Group(group) if group.r#type == ChannelType::OrgMsg)
                    {
                        let mut org_captures =
                            org_regex.captures_iter(&group_message_packet.message.text);

                        let guild = if let Some(capture) = org_captures.next() {
                            capture[2].to_string()
                        } else {
                            continue;
                        };

                        info!("Tower attack by guild: {}", guild);

                        let params =
                            serde_urlencoded::to_string(&[("enabled", "1"), ("org_name", &guild)])
                                .unwrap();

                        let request = Request::builder()
                            .uri(format!("https://tower-api.jkbff.com/api/towers?{}", params))
                            .method("GET")
                            .header("User-Agent", "TowerAttackCache")
                            .body(Body::empty())
                            .unwrap();

                        let response = client.request(request).await.unwrap();
                        let body = hyper::body::to_bytes(response).await.unwrap();

                        let site_json: SearchResult =
                            if let Ok(result) = serde_json::from_slice(&body) {
                                result
                            } else {
                                error!("Failed to parse sites JSON: {:?}", body);
                                continue;
                            };

                        info!("Setting {} sites as hot", site_json.count);

                        let mut hot_sites = hot_sites.write().expect("rwlock poisoned");
                        let hot_at = Instant::now();
                        for site in site_json.results {
                            hot_sites.insert((site.playfield_id, site.site_number), (site, hot_at));
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let host_raw = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let host = IpAddr::from_str(&host_raw)?;
    let port = env::var("PORT").unwrap_or_else(|_| "7880".into()).parse()?;

    let hot_sites: HotSites = Arc::new(RwLock::new(HashMap::new()));

    tokio::spawn(chat_client(hot_sites.clone()));
    tokio::spawn(cleanup_task(hot_sites.clone()));

    let address = SocketAddr::from((host, port));

    let service = make_service_fn(move |addr: &AddrStream| {
        trace!("Connection from: {:?}", addr);
        let hot_sites = hot_sites.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |_req| {
                let hot_sites = hot_sites.read().expect("rwlock poisoned");
                let hot: Vec<&TowerSite> = hot_sites.values().map(|(s, _)| s).collect();
                let sites_json = serde_json::to_vec(&hot).unwrap();

                async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("Content-Type", "application/json")
                            .body(Body::from(sites_json))
                            .unwrap(),
                    )
                }
            }))
        }
    });

    let server = Server::bind(&address).serve(service);

    let graceful = server.with_graceful_shutdown(shutdown_signal());

    info!("Listening on http://{}", address);

    if let Err(why) = graceful.await {
        error!("Fatal server error: {}", why);
    }

    Ok(())
}

#[cfg(windows)]
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
    };
}

fn main() -> Result<(), Box<dyn Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run())
}
