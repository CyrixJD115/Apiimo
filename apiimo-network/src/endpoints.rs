//! Endpoint registry recovered from the Steam build.
//!
//! Sources: `stringliteral.json` (45,240 literals), `dump.cs` class surface
//! (`ProfileApiClient`/`FunPlus.WorldX.Utils.WorldXProfiler`, `SDK.FPC.dll`
//! classes, XPatch manifests), and REPORT.md. The registry distinguishes
//! production/stage/dev environments and public/internal classes: the
//! `10.8.x.x` internal services are dev plant that shipped in production
//! strings and are recorded for documentation, not for use.

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
    /// FunPlus account / platform services.
    FunPlusPlatform,
    /// Anti-cheat / telemetry.
    Telemetry,
    /// Analytics / attribution.
    Analytics,
    /// Content CDN / patch pipeline.
    ContentDelivery,
    /// Supporting service (translation, IP echo, store, docs).
    Auxiliary,
    /// Internal-only service that must not be contacted.
    Internal,
}

/// One known endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Scheme plus host (and port when non-default), e.g. `https://worldx-office-api.aniimo.com`.
    pub host: &'static str,
    /// Request path or path template (`{0}`-style format slots as shipped).
    pub path: &'static str,
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
            purpose,
            environment,
            class,
        }
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
];
