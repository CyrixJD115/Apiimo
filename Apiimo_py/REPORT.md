# Aniimo — Full RE Report
**Game:** Aniimo (FunPlus / Polaris Quest) · Unity 2022.3.62f1 · IL2CPP metadata v31
**Scope:** Anti-cheat, server data pipeline (session loading), network surface, internal infrastructure
**Source:** `./.dump/` (decrypted metadata + full Il2CppDumper output)

---

## 1. ANTI-CHEAT

### 1.1 NetEase Yidun / HTPSec (primary anti-cheat)
Three wrapper layers exist in the metadata (`NTESHTPSec`, `NTES*` mobile variants, `NetEase`):

**`NTESRiskSecProtect` : MonoBehaviour** — main entry:
- `init(productId, InitCallback)` — SDK boot
- `setRoleInfo(businessId, roleId, roleName, roleAccount, roleServer, serverid, gameJson)` — player identity binding
- **`getToken(timeout, businessId) -> AntiCheatResult`** — per-action anti-cheat tokens; the server validates these on every protected request (async variant: `getTokenAsyncCallback`, `TokenBlockCallback`)
- **`getDataSign(inputData)`** — request payload signing
- **`ioctl(RequestCmdID, data)`** — native command channel

**`RequestCmdID`** (native commands):
```
Cmd_GetSignInfo  Cmd_IsRootDevice  Cmd_GetHTPVersion
Cmd_GetCollectData  Cmd_SetConfigData  Cmd_SetResponseData  Cmd_GetDeviceId
```

**`SafeCommResult`** — encrypted server channel status codes:
```
SC_CODE_OK  SC_FILE_NOTEXIST  SC_FILE_IS_BROKEN  SC_PROTOCOL_VERSION_ERROR
SC_PARAM_ERROR  SC_DATA_TAMPERED  SC_DATA_DECRYPT_ERROR  SC_ALG_ERROR
SC_TIMEOUT  SC_ENV  SC_DEVICE  SC_NOT_INIT  SC_CLOSED
SC_BUFF_MALLOC_ERROR  SC_INSIDE_ERROR  (+ SC_NOSUPPORT in v2 variant)
```

**`SafeComm` encrypted transport:**
- `safeCommToServer / safeCommToServerByte(alg, data, size, ...)`
- `safeCommFromServer / safeCommFromServerByte(alg, timeout, ...)`
- `safeCommToServerV30 / safeCommToServerByteV30(version, alg, data, isCrucial)` — v3 protocol with "crucial" flag
- **`htpSign(alg, version, inputData)`** — HTTP request signing (headers layer)

**`NetEase.AntiCheatResult`** error codes: `OK`, `ERROR_NOT_INIT`, `ERROR_ON_MAIN`, `ERROR_BUSINESSID_INVALID`, `ERROR_GEN_TOKEN`.
**`NetSecProtect`** (mobile/AndroidJavaObject variant) + `HTProtectConfig`, `HTPCallback`.

**Takeaway:** client is a *sensor + signer*; enforcement is server-side via the `businessId` tokens and signed payloads. Bypassing the client does NOT bypass the server check.

### 1.2 Supporting defense stack
| Component | File | Role |
|---|---|---|
| NEP2 | `NEP2.dll` | NetEase P2P/network lib |
| NamedPipe bridge | `NamedPipeClient.dll` + `XCloudPipeController.IsPipeConnected/SendPipeJson` | out-of-process IPC (cloud host / sidecar channel) |
| GME | `GMESDK.dll` | Tencent Game Multimedia Engine (voice) |
| CrashSight | `CrashSight64.dll` | Tencent crash/ANR reporting (`/pb/async` endpoints) |
| pxauth | `pxauth.dll`, `pxauth_en.dll` | FunPlus auth library |
| FPX | `FPX.dll`, `FPXGame.dll`, `FPXSteam.dll`, `fpx_config_pc`, `fpx_md5sums`, `fpx_ver.txt` | FunPlus platform/account SDK |
| sqlite | `sqlite3worldx.dll` | local DB (save cache) |
| Meta-encryption | `global-metadata.dat` | full-file 1152-byte repeating-XOR + reordered sections + scrambled header (defeated — see Apiimo) |

**Not present:** Easy Anti-Cheat, BattlEye, Vanguard, Denuvo.

---

## 2. HOW THE GAME PULLS PLAYER SESSION DATA

### 2.1 Login chain
```
Platform (Steam / mobile / Discord)
   └─> FPX SDK (FPXSteam / FPXWin / FPXCompat : IFPXPlatform)
         Init(data) / Call(module, func, parameters)  <- generic module RPC
   └─> pxauth.dll  (auth code -> ticket)
   └─> SDKManager.Init(FPXCallback) / InitFromLua / reInitFromLua
   └─> XCloudPipeController fills session fields:
         CMDAutoLogin, CMDFPSDKCode, CMDFPSDKChannelUID,
         CMDFPSDKAccountID, CMDFPSDKTicket, CMDFPSDKSession, CMDFPSDKTrackInfo
   └─> CMDAutoLoginFromLua()  <- xLua drives the login sequence
   └─> ProfileApiClient -> worldx-office-api.aniimo.com
```

### 2.2 Session/profile data (the "load my game" pull)
- **`ProfileApiClient`** — generic JSON client: `SendJson<TRequest, TResponse>(path, body, done)`, `SendRequest<TResponse>`, `SendWithoutBody<TResponse>`
- Endpoints:
  - `/profile-sessions/start` — **start/restore the active player session**
  - `/profile-sessions/` — session profile operations
  - `/api/init` — bootstrap
  - `/api/activity/initEvent`, `/api/v2/notice`, `/api/fpx/notice` — live-ops/notifications
  - `/api/upload/avatar`, `/api/performance/external/score`
- Hosts (prod + fallback + dev): `worldx-office-api.aniimo.com`, `worldx-office-api.yimo.com`, `worldx-office-api-stage.aniimo.com`, `worldx-office-api-stage.yimo.com`
- Auth headers observed: `Authorization`, `X-ApiKey`; login strings: `ConnectWithToken`, `CaptureTokenPayload`, `CMDAutoLoginFromLua`, `loginFromMobile`

### 2.3 Content/patch pipeline (XPatch + YooAsset)
- Manifests: `/xpatch_update_save_data.json`, `/xpatch_update_lua_save_data.json`, `/xpatch_update_ucs_save_data.json`, `/xpatch_update_xfs_save_data.json`, `{0}/extpack_save_data.json`
- Version lists: `fpxvList.txt`, `dev_fpxvList.txt`, `downloader.txt`, `RemoteConfig.json`, `fpxver`
- Packages: **`.xdf`** containers (AES-encrypted zips — `ZipFile` compat layer explicitly rejects zip-native AES: *"AES encrypted XDF zip entries are not supported"*), `.xdv` volumes (`extpack.xdv`, `{0}_patchv2/root/{1}.xdv`, `_repair.xdv`)
- Sub-systems: `LuaScripts.xdf` (**hot-pushable Lua game code**), UCS scripts (`/ucsscripts/{0}/`), XFS resource files
- Flow: `XPatchRemoteConfigMgr` (remote config / step-down rules `V2StepDownRemoteConfig`) → `PatchHttpClient` (retry/upload/test logic) → `XPatchActionRunner`/`XPatchExtPack` (download → `CRExtractVolume`) → `AfterPatchResolveUCS`

### 2.4 Save model (local + world parts)
- `XFilePack<TKey,T>` / `XFilePackManager` / `XFilePackHeader` / `XSerializationLoader` — custom serialized object packs (Unity JobSystem loaders: `XFilePackLoadJob`, `XSerializationLoadJob`)
- `.xdv` volumes = world data containers (`ContainerVolume`, `SetFromXDV`)
- **`V2SaveHelper`**: `XPatchV2SaveGlobal` (global save) + `XPatchV2SaveModule` per data type + `XPatchV2SavePartClassDetail` per class; `SyncWorldPartToGlobal(...)`, `SavePatchV2Global/PartData`, `LoadPatchV2Global/PartData`, `GetUserSave(v2g, user)` / `SetUserSavePart(v2g, user, partid)` — per-user world-part save modules
- Save build paths leaked: `C:\Users\Administrator\Desktop\temp\abuild\250708\out\save`

### 2.5 Multiplayer session
- ECS networking: `SyncSystem`, `EcsSyncSendQueue`, `EcsSyncReceiveQueue` (server-authoritative state sync)
- `CreateMatchmaker`, WebSockets (Mono client stack), `AcquireSetupSession`, `BeginPremiumFeatureSession`/`EndPremiumFeatureSession`

### 2.6 xLua bridge
- `LuaManager`, `LuaEnv` + `XLua.CSObjectWrap` (591 wrappers) — large parts of game logic live in Lua delivered via `LuaScripts.xdf`, hot-updatable server-side; Lua calls into C# (`CMDAutoLoginFromLua`, `InitFromLua`, `SendCloudHostFullFromLua`, `RecvCloudHostFullFromLua`, `SendPipeJson`)

---

## 3. INTERNAL INFRASTRUCTURE (dev/plant in production strings)

### 3.1 Internal IPs
| Endpoint | Purpose (inferred) |
|---|---|
| `http://10.7.69.61:5930` | internal service (bare HTTP) |
| `http://10.8.43.244:8070/temp/xcloud/demox/` | xcloud demo/dev storage |
| `http://10.8.43.49:8049/download?md5={0}&len={1}` | internal file download (md5-verified) |
| `http://10.8.43.49:8049/upload` | internal file upload |
| `http://10.8.43.49:8090/cdn/obj/rt-game-alisg/worldx/dev/RemoteConfig.json` | dev remote config (aliSG CDN origin) |
| `http://10.8.43.49:8090/cdn/obj/rt-game-alisg/worldx/dev/downloader.txt` | dev downloader manifest |
| `http://10.8.43.49:8090/cdn/obj/rt-game-alisg/worldx/{dev,release}/fpxvList.txt` | dev/release version lists |
| `http://10.8.45.121:3008/api/v1` | internal API v1 |
| `http://10.8.45.62:8063/myhttp/api/json` | internal JSON API |
| `http://10.8.45.67:3007/api/lark_platform/write_table` | **Feishu/Lark table writer** (internal tooling) |
| `http://10.8.45.67:3007/api/lark_platform/create_and_write_table_async` | Feishu/Lark async table creator |
| `http://10.8.45.67:3008/` | internal service |
| `http://10.8.45.67:3106/gen_id` | internal ID generator |
| `http://10.8.45.67:8080/api/auth/users?user_p4=` | internal user auth query (P4 = Perforce?) |
| `http://10.8.45.77:6667/api/report` | internal reporting |

### 3.2 Production hosts (68 hosts total, grouped)
**Game APIs:** `worldx-office-api.aniimo.com` (+ `.yimo.com`, `-stage` variants)
**FunPlus platform:** `fpcs-web.funplus.com`, `sscs-web.funplus.com/pc`, `fp-toolskit.funplus.com(.cn)/openapi/location`, `fp-logagent-stage.funplus.com.cn/log_tag`, `worldx.funplus.com:8080/api/autotest/client-errors/add` + `/api/basic/upload`
**KingsGroup (FunPlus brand):** `ss-community.kingsgroupgames.com`, `st-store-coin.kingsgroupgames.com/api/products` (store)
**Tencent:** `console.crashsight.wetest.net/pb/async`, `ps5.crashsight.qq.com/pb/async`
**NetEase:** `uu.163.com/?channel=yimo` (UU network accelerator)
**Attribution/analytics:** `events.appsflyer.com/v1.0/c2s/`, `sandbox-events.appsflyer.com`
**Misc:** `api.ipify.org` / `api.ipify.cn` (public IP detection), `openapi.youdao.com/api` (YouDao translation), `www.aniimo.com`, `yimo.com/cloud_download`, `www.yimoo.com`, `itunes.apple.com/app/id6796757624`, `srdebugger.stompyrobot.uk` (SRDebugger), `database.windows.net` / `chinacloudapi.cn` / `usgovcloudapi.net` (Azure SQL templates), `ss-community.kingsgroupgames.com`

### 3.3 API paths (complete found set)
```
/api/init                              /api/activity/initEvent
/api/v2/notice                         /api/fpx/notice
/api/upload/avatar                     /api/performance/external/score
/profile-sessions                      /profile-sessions/start
/api/autotest/client-errors/add        /api/basic/upload
/api/auth/users?user_p4=               /api/lark_platform/write_table
/api/lark_platform/create_and_write_table_async              /api/report
/gen_id                                /api/v1
/openapi/location                      /myhttp/api/json
/api/products
```

---

## 4. BONUS FINDS

- **Build plant:** `C:\Users\Administrator\Desktop\temp\abuild\250708\out\save`, `...\cmdtest\genmd5\mygame`, `E:\game_test\worldx_Data\cvs\res\fpxver`, `manifest_1000.bytes` / `xbt` test artifacts
- **Alternative brand:** the game ships under a second identity — `yimo.com` / `www.yimoo.com` / `channel=yimo` (CN release alias of Aniimo)
- **UCS/UCS-scripts:** server-pushed script channel (`/ucsscripts/{0}/`, `AfterPatchResolveUCS`)
- **Version fingerprint strings:** `PrintGameVersionInfo: deploy[{0}], scm[{1}], res[{2}], lua[{3}], ucs[{4}]`
- **SRDebugger** (StompyRobot in-game debug console) + `RuntimeInspector.Runtime` shipped in release
- **Odin / Sirenix** serializer (+ link to their BitBucket issue), Newtonsoft JSON, Fullserializer
- **YouDao translation API** integrated (client-side translation calls)
- **Public IP check** via ipify (both .org and .cn mirror) — region detection
- **`XPatchExtPack`** downloads + extracts "ext packs" in threads (`CRExtractVolume`, `CRThreadExtractVolume`)
- **xLua** VM with 591 CSObjectWrap bindings — `FunPlusWorldXManagerLuaManagerWrap` exposes the manager layer to Lua; logic hot-patchable via `LuaScripts.xdf`
- **FlowCanvas.WorldX.Server** node set — visual-scripted server behaviors
- **Discord** auth flow (token callback, "Discord authorization successful")
- **Steam** (`steam_api64.dll`, `FPXSteam`) + PlayStation strings (`ps5.crashsight.qq.com`) — multi-platform sku

---

## 5. QUICK REFERENCE — key classes
| Class | Role |
|---|---|
| `NTESRiskSecProtect` / `NetSecProtect` | NetEase Yidun anti-cheat wrapper |
| `AntiCheatResult` / `SafeCommResult` / `RequestCmdID` | token + encrypted-comm contracts |
| `XCloudPipeController` | Lua ↔ native pipe bridge, session CMD fields |
| `ProfileApiClient` | JSON client → worldx-office-api (profile sessions) |
| `SDKManager` | SDK lifecycle, CrashSight init, login-from-Lua |
| `XPatchRemoteConfigMgr` / `PatchHttpClient` | remote config + patch downloads |
| `V2SaveHelper` / `XPatchV2SaveHelper` | save global/part model, world-part sync |
| `XFilePackManager` / `XSerializationLoader` | XDF/XDV serialized asset/save packs |
| `LuaManager` / `LuaEnv` | xLua VM (server-hot-patchable logic) |
| `EcsSyncSystem` + send/receive queues | multiplayer state sync |
| `FPXWin` / `FPXSteam` / `FPXCompat` | platform abstraction (IFPXPlatform) |
