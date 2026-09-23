//! Endpoint registry recovered from the Steam build and a live session.
//!
//! Sources: `stringliteral.json` (45,240 literals), `dump.cs` class surface,
//! REPORT.md, and the 2026-09-21 live login (FPX `fpxui.log` and the
//! `PHONESTCORE_HOOK` connection log in `Player.log`). The registry
//! distinguishes production/stage/dev environments and public/internal
//! classes: the `10.8.x.x` internal services are dev plant that shipped in
//! production strings and are recorded for documentation, not for use.

use serde::{Deserialize, Serialize};

/// Deployment environment an endpoint belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointEnvironment {
    /// Live production traffic.
    Production,
    /// Staging (`-stage` hosts).
    Stage,
    /// Development plant leaked into production strings (internal IPs).
    Development,
}

/// What kind of service the endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointClass {
    /// Game session/office API.
    GameApi,
    /// Game gate: the KCP/websocket world-connection endpoints (host:port,
    /// no HTTP scheme).
    GameGate,
    /// FunPlus account / platform services.
    FunPlusPlatform,
    /// Anti-cheat / telemetry.
    Telemetry,
    /// Analytics / attribution.
    Analytics,
    /// Content CDN / patch pipeline.
    ContentDelivery,
    /// Per-player object storage (Aliyun OSS).
    ObjectStorage,
    /// Payment / IAP services.
    Payment,
    /// Supporting service (translation, IP echo, store, docs).
    Auxiliary,
    /// Internal-only service that must not be contacted.
    Internal,
}

/// One known endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Scheme plus host (and port when non-default), e.g. `https://worldx-office-api.aniimo.com`.
    /// Gate endpoints carry only the hostname here and their port in
    /// [`Endpoint::port`].
    pub host: &'static str,
    /// Request path or path template (`{0}`-style format slots as shipped).
    pub path: &'static str,
    /// Non-default port (gates, and HTTP services on explicit ports).
    pub port: Option<u16>,
    pub purpose: &'static str,
    pub environment: EndpointEnvironment,
    pub class: EndpointClass,
}

impl Endpoint {
    pub const fn new(
        host: &'static str,
        path: &'static str,
        purpose: &'static str,
        environment: EndpointEnvironment,
        class: EndpointClass,
    ) -> Self {
        Self {
            host,
            path,
            port: None,
            purpose,
            environment,
            class,
        }
    }

    /// Attach an explicit port (gate endpoints).
    pub const fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// The class of every internal-IP endpoint.
    pub fn is_internal(&self) -> bool {
        self.class == EndpointClass::Internal
    }
}

const fn game(host: &'static str, path: &'static str, purpose: &'static str) -> Endpoint {
    Endpoint::new(
        host,
        path,
        purpose,
        EndpointEnvironment::Production,
        EndpointClass::GameApi,
    )
}

const fn stage(host: &'static str, path: &'static str, purpose: &'static str) -> Endpoint {
    Endpoint::new(
        host,
        path,
        purpose,
        EndpointEnvironment::Stage,
        EndpointClass::GameApi,
    )
}

const fn fp(host: &'static str, path: &'static str, purpose: &'static str) -> Endpoint {
    Endpoint::new(
        host,
        path,
        purpose,
        EndpointEnvironment::Production,
        EndpointClass::FunPlusPlatform,
    )
}

const fn aux(host: &'static str, path: &'static str, purpose: &'static str) -> Endpoint {
    Endpoint::new(
        host,
        path,
        purpose,
        EndpointEnvironment::Production,
        EndpointClass::Auxiliary,
    )
}

const fn gate(host: &'static str, port: u16, purpose: &'static str) -> Endpoint {
    Endpoint::new(
        host,
        "",
        purpose,
        EndpointEnvironment::Production,
        EndpointClass::GameGate,
    )
    .with_port(port)
}

const fn oss(host: &'static str, path: &'static str, purpose: &'static str) -> Endpoint {
    Endpoint::new(
        host,
        path,
        purpose,
        EndpointEnvironment::Production,
        EndpointClass::ObjectStorage,
    )
}

const fn pay(host: &'static str, path: &'static str, purpose: &'static str) -> Endpoint {
    Endpoint::new(
        host,
        path,
        purpose,
        EndpointEnvironment::Production,
        EndpointClass::Payment,
    )
}

const fn internal(host: &'static str, path: &'static str, purpose: &'static str) -> Endpoint {
    Endpoint::new(
        host,
        path,
        purpose,
        EndpointEnvironment::Development,
        EndpointClass::Internal,
    )
}

const fn cdn(host: &'static str, path: &'static str, purpose: &'static str) -> Endpoint {
    Endpoint::new(
        host,
        path,
        purpose,
        EndpointEnvironment::Production,
        EndpointClass::ContentDelivery,
    )
}

/// Every endpoint recovered from the build, grouped by service.
pub const ENDPOINTS: &[Endpoint] = &[
    // -- game office API (session bootstrap, notices, profiling sessions) --
    game(
        "https://worldx-office-api.aniimo.com",
        "/api/init",
        "bootstrap config",
    ),
    game(
        "https://worldx-office-api.aniimo.com",
        "/api/activity/initEvent",
        "live-ops events",
    ),
    game(
        "https://worldx-office-api.aniimo.com",
        "/api/v2/notice",
        "notices",
    ),
    game(
        "https://worldx-office-api.aniimo.com",
        "/api/fpx/notice",
        "FPX SDK notices",
    ),
    game(
        "https://worldx-office-api.aniimo.com",
        "/api/upload/avatar",
        "avatar upload",
    ),
    game(
        "https://worldx-office-api.aniimo.com",
        "/api/performance/external/score",
        "performance score upload",
    ),
    game(
        "https://worldx-office-api.aniimo.com",
        "/profile-sessions/start",
        "WorldXProfiler session start (telemetry, not save data)",
    ),
    game(
        "https://worldx-office-api.aniimo.com",
        "/profile-sessions/{id}",
        "WorldXProfiler session ops",
    ),
    game(
        "https://worldx-office-api.yimo.com",
        "/api/init",
        "CN alias bootstrap",
    ),
    stage(
        "https://worldx-office-api-stage.aniimo.com",
        "/api/init",
        "staging bootstrap",
    ),
    stage(
        "https://worldx-office-api-stage.yimo.com",
        "/api/init",
        "CN staging bootstrap",
    ),
    // -- FunPlus platform (account, cloud save, community, store) --
    fp(
        "https://fpcs-web.funplus.com",
        "",
        "FunPlus cloud-save web service",
    ),
    fp(
        "https://sscs-web.funplus.com",
        "/pc",
        "FunPlus session/console service (PC)",
    ),
    fp(
        "https://fp-toolskit.funplus.com",
        "/openapi/location",
        "geo location",
    ),
    fp(
        "https://fp-toolskit.funplus.com.cn",
        "/openapi/location",
        "geo location (CN)",
    ),
    fp(
        "https://fp-logagent-stage.funplus.com.cn",
        "/log_tag",
        "log agent (stage)",
    ),
    fp(
        "https://worldx.funplus.com:8080",
        "/api/autotest/client-errors/add",
        "client error reporting",
    ),
    fp(
        "https://worldx.funplus.com:8080",
        "/api/basic/upload",
        "basic upload",
    ),
    fp(
        "https://ss-community.kingsgroupgames.com",
        "",
        "KingsGroup community",
    ),
    fp(
        "https://st-store-coin.kingsgroupgames.com",
        "/api/products",
        "store products",
    ),
    // -- content delivery (XPatch manifests, version lists, scripts) --
    cdn(
        "",
        "/xpatch_update_save_data.json",
        "save-data patch manifest",
    ),
    cdn(
        "",
        "/xpatch_update_lua_save_data.json",
        "Lua save-data manifest",
    ),
    cdn(
        "",
        "/xpatch_update_ucs_save_data.json",
        "UCS save-data manifest",
    ),
    cdn(
        "",
        "/xpatch_update_xfs_save_data.json",
        "XFS save-data manifest",
    ),
    cdn(
        "",
        "/extpack_save_data.json",
        "ext-pack manifest ({0}/ prefix)",
    ),
    cdn("", "/RemoteConfig.json", "remote config"),
    cdn("", "/fpxvList.txt", "version list"),
    cdn("", "/downloader.txt", "downloader manifest"),
    cdn("", "/ucsscripts/{0}/", "server-pushed UCS scripts"),
    // -- telemetry / anti-cheat / analytics --
    Endpoint::new(
        "https://console.crashsight.wetest.net",
        "/pb/async",
        "CrashSight telemetry",
        EndpointEnvironment::Production,
        EndpointClass::Telemetry,
    ),
    Endpoint::new(
        "https://ps5.crashsight.qq.com",
        "/pb/async",
        "CrashSight telemetry (PS5)",
        EndpointEnvironment::Production,
        EndpointClass::Telemetry,
    ),
    Endpoint::new(
        "https://events.appsflyer.com",
        "/v1.0/c2s/",
        "AppsFlyer attribution",
        EndpointEnvironment::Production,
        EndpointClass::Analytics,
    ),
    Endpoint::new(
        "https://sandbox-events.appsflyer.com",
        "/v1.0/c2s/",
        "AppsFlyer sandbox",
        EndpointEnvironment::Stage,
        EndpointClass::Analytics,
    ),
    // -- auxiliary --
    aux("https://api.ipify.org", "", "public IP detection"),
    aux("https://api.ipify.cn", "", "public IP detection (CN)"),
    aux("https://openapi.youdao.com", "/api", "YouDao translation"),
    aux(
        "https://uu.163.com",
        "/?channel=yimo",
        "NetEase UU accelerator",
    ),
    aux("https://www.aniimo.com", "", "web presence"),
    aux(
        "https://yimo.com",
        "/cloud_download",
        "CN cloud download page",
    ),
    aux(
        "https://itunes.apple.com",
        "/app/id6796757624",
        "App Store listing",
    ),
    // -- internal dev plant (documentation only; unreachable from outside) --
    internal("http://10.7.69.61:5930", "", "internal service"),
    internal(
        "http://10.8.43.244:8070",
        "/temp/xcloud/demox/",
        "xcloud demo storage",
    ),
    internal(
        "http://10.8.43.49:8049",
        "/download?md5={0}&len={1}",
        "md5 file download",
    ),
    internal("http://10.8.43.49:8049", "/upload", "internal upload"),
    internal(
        "http://10.8.43.49:8090",
        "/cdn/obj/rt-game-alisg/worldx/dev/RemoteConfig.json",
        "dev remote config",
    ),
    internal(
        "http://10.8.43.49:8090",
        "/cdn/obj/rt-game-alisg/worldx/{dev,release}/fpxvList.txt",
        "version lists",
    ),
    internal(
        "http://10.8.43.49:8090",
        "/cdn/obj/rt-game-alisg/worldx/dev/downloader.txt",
        "downloader manifest",
    ),
    internal("http://10.8.45.121:3008", "/api/v1", "internal API v1"),
    internal(
        "http://10.8.45.62:8063",
        "/myhttp/api/json",
        "internal JSON API",
    ),
    internal(
        "http://10.8.45.67:3007",
        "/api/lark_platform/write_table",
        "Feishu/Lark table writer",
    ),
    internal(
        "http://10.8.45.67:3007",
        "/api/lark_platform/create_and_write_table_async",
        "Feishu/Lark async tables",
    ),
    internal("http://10.8.45.67:3008", "", "internal service"),
    internal("http://10.8.45.67:3106", "/gen_id", "internal ID generator"),
    internal(
        "http://10.8.45.67:8080",
        "/api/auth/users?user_p4={0}",
        "internal user query (Perforce)",
    ),
    internal(
        "http://10.8.45.77:6667",
        "/api/report",
        "internal reporting",
    ),
    // ------------------------------------------------------------------
    // Live-session findings (2026-09-21): FPX bootstrap, payment, identity,
    // announcement APIs, the game gates, per-player OSS buckets, and the
    // public server-list CDN. Sources: fpxui.log, Player.log
    // (PHONESTCORE_HOOK), and the fetched server_list_publish.json.
    // ------------------------------------------------------------------
    // -- FPX bootstrap ("store URL manager", endpoint 1800) --
    Endpoint::new(
        "https://worldx-ame.kingsgroupgames.com",
        "/do/?p0=pc&p1=9&p2=1800&p3=api&g=worldx_global",
        "FPX bootstrap: URLs, app_id/app_secret, IAP keys",
        EndpointEnvironment::Production,
        EndpointClass::FunPlusPlatform,
    ),
    // -- announcements / platform APIs seen in the live session --
    Endpoint::new(
        "https://announcement-web.funplus.com",
        "/api/announce/list",
        "announcement list",
        EndpointEnvironment::Production,
        EndpointClass::FunPlusPlatform,
    ),
    Endpoint::new(
        "https://priv-platform-yimoo-api.funplus.com",
        "/api/game/red-dot",
        "red-dot (unread-badge) state",
        EndpointEnvironment::Production,
        EndpointClass::FunPlusPlatform,
    ),
    // -- identity / auth / account (from the FPX bootstrap config) --
    Endpoint::new(
        "https://fp-idauth-stage.funplus.com.cn",
        "",
        "FunPlus id-auth service",
        EndpointEnvironment::Stage,
        EndpointClass::FunPlusPlatform,
    ),
    Endpoint::new(
        "https://store-funplusid-stage.funplus.com",
        "",
        "account HTML (FunPlus ID store)",
        EndpointEnvironment::Stage,
        EndpointClass::FunPlusPlatform,
    ),
    Endpoint::new(
        "http://store-account-test.funplus.com",
        "",
        "roleInfoApiServer (test)",
        EndpointEnvironment::Development,
        EndpointClass::FunPlusPlatform,
    ),
    Endpoint::new(
        "http://35.166.237.230:8989",
        "",
        "funplusApiServer (AWS, from bootstrap config)",
        EndpointEnvironment::Development,
        EndpointClass::FunPlusPlatform,
    ),
    Endpoint::new(
        "http://47.100.233.173:10302",
        "/api/version/list",
        "versionConfig (Aliyun, from bootstrap config)",
        EndpointEnvironment::Development,
        EndpointClass::FunPlusPlatform,
    ),
    Endpoint::new(
        "https://st.kingsgroupgames.com",
        "/pc/faq",
        "FAQ / login FAQ pages",
        EndpointEnvironment::Production,
        EndpointClass::Auxiliary,
    ),
    Endpoint::new(
        "https://kg-img-upload-test.funplus.com.cn",
        "",
        "image upload (test)",
        EndpointEnvironment::Development,
        EndpointClass::FunPlusPlatform,
    ),
    Endpoint::new(
        "http://upload-s3.funplus.com",
        "/api/upload_s3",
        "S3 upload service",
        EndpointEnvironment::Production,
        EndpointClass::FunPlusPlatform,
    ),
    // -- payment / IAP --
    pay(
        "https://fp-payment-worldx.kingsgroupgames.com",
        "",
        "payment API",
    ),
    pay(
        "https://fp-payment-worldx-backup.kingsgroupgames.com",
        "",
        "payment API (backup)",
    ),
    // -- public server-list CDN --
    cdn(
        "https://worldx-global-cdn.kingsgroupgames.com",
        "/server_list/server_list_publish.json",
        "server list (public, unauthenticated)",
    ),
    cdn(
        "https://worldx-global-cdn-backup.kingsgroupgames.com",
        "/server_list/server_list_publish.json",
        "server list (backup CDN)",
    ),
    // -- office API public CMS surface (recovered from the official website's
    //    NUXT chunks, verified live 2026-09-22; Region header = locale) --
    Endpoint::new(
        "https://worldx-office-api.aniimo.com",
        "/api/subscribe/appoint",
        "global pre-registration counter (no auth): {current_count}",
        EndpointEnvironment::Production,
        EndpointClass::GameApi,
    ),
    Endpoint::new(
        "https://worldx-office-api.aniimo.com",
        "/api/idle/info?region={locale}",
        "website feature-carousel CMS records",
        EndpointEnvironment::Production,
        EndpointClass::GameApi,
    ),
    Endpoint::new(
        "https://worldx-office-api.aniimo.com",
        "/api/bg/video?region={locale}",
        "website background video/poster CMS",
        EndpointEnvironment::Production,
        EndpointClass::GameApi,
    ),
    Endpoint::new(
        "https://worldx-office-api.aniimo.com",
        "/api/share/site?position={pos}",
        "website share-site links",
        EndpointEnvironment::Production,
        EndpointClass::GameApi,
    ),
    Endpoint::new(
        "https://worldx-office-api.aniimo.com",
        "/api/agreement/list?region={locale}",
        "website footer agreements",
        EndpointEnvironment::Production,
        EndpointClass::GameApi,
    ),
    Endpoint::new(
        "https://worldx-office-api.aniimo.com",
        "/api/player/login",
        "website account login (credentials required)",
        EndpointEnvironment::Production,
        EndpointClass::GameApi,
    ),
    // -- website / web-store CDNs and fronts (2026-09-22 crawl) --
    Endpoint::new(
        "https://worldx-website-cdn.aniimo.com",
        "/official-website/worldx-global-stage/office/aniimo/{file}",
        "website media CDN (OSS bucket worldx-website; listing denied)",
        EndpointEnvironment::Production,
        EndpointClass::ContentDelivery,
    ),
    Endpoint::new(
        "https://kg-web-cdn.akamaized.net",
        "/master/official-website/worldx_office_frontend/_nuxt/{chunk}.js",
        "official-website JS chunks (KingsGroup web CDN, Akamai)",
        EndpointEnvironment::Production,
        EndpointClass::ContentDelivery,
    ),
    Endpoint::new(
        "https://store.aniimo.com",
        "/aniimo/pc-checkout/",
        "PC web checkout (web-pay-hub SPA)",
        EndpointEnvironment::Production,
        EndpointClass::Payment,
    ),
    Endpoint::new(
        "https://worldx-store.funplus.com",
        "/aniimo/sdk/",
        "in-game SDK store page (web-pay-hub SPA)",
        EndpointEnvironment::Production,
        EndpointClass::Payment,
    ),
    // -- cluster ms-gates at :26000 and master gates (server list 2026-09-22;
    //    the :26000 cluster gates and ap/eu masters answer probes and issue
    //    tokens + m19 gate-info even while the close gates are FORBIDDEN) --
    gate("47.254.146.32", 26000, "Russia cluster ms-gate"),
    gate("47.253.51.106", 26000, "SHH cluster ms-gate"),
    gate("47.252.31.70", 26000, "Review-Global cluster ms-gate"),
    gate("47.236.60.219", 26000, "CONSOLE-Review cluster ms-gate"),
    gate("47.236.102.145", 26000, "VN cluster ms-gate"),
    gate("47.236.82.169", 26000, "Pioneer cluster ms-gate (refused 2026-09-22)"),
    gate(
        "worldx-ap-master-ms-gate.kingsgroupgames.com",
        10000,
        "AP master ms-gate",
    ),
    gate(
        "worldx-eu-master-ms-gate.kingsgroupgames.com",
        10000,
        "EU master ms-gate",
    ),
    gate(
        "172.65.184.138",
        10000,
        "Aniimo-OST test cluster ms-gate (FORBID when probed)",
    ),
    // -- per-player object storage (presigned OSS4 URLs, 300s expiry) --
    oss(
        "https://worldx-global-assets.oss-us-east-1.aliyuncs.com",
        "/us/prod/ClientInfo/{uid}_client_info_bin",
        "per-player client-info blob (synced every ~3 min)",
    ),
    oss(
        "https://worldx-global-assets.oss-us-east-1.aliyuncs.com",
        "/us/prod/pet_jewelry/{uid}",
        "per-player pet data",
    ),
    // -- game gates (KCP primary; raw host:port, observed live) --
    gate(
        "worldx-us-prod-singleworld-1000-gate.kingsgroupgames.com",
        20000,
        "single-world 1000 gate (the live account's world)",
    ),
    gate(
        "worldx-us-prod-ms-gate-close.kingsgroupgames.com",
        10000,
        "US matchmaking-service gate",
    ),
    gate(
        "worldx-ap-prod-ms-gate-close.kingsgroupgames.com",
        10000,
        "AP matchmaking-service gate",
    ),
    gate(
        "eu-prod-ms.worldx-gate.kingsgroupgames.com",
        10000,
        "EU matchmaking-service gate",
    ),
    gate(
        "47.89.130.56",
        20000,
        "game gate (raw Aliyun IP observed live)",
    ),
    gate(
        "47.253.243.54",
        10000,
        "US MS gate (raw Aliyun IP, from server list)",
    ),
    gate(
        "47.245.180.147",
        10000,
        "EU MS gate (raw Aliyun IP, from server list)",
    ),
];
