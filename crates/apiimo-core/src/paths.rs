use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{io_error, Error};

/// Relative path to Aniimo's encrypted metadata file.
pub const METADATA_REL: &str = "Aniimo_Data/il2cpp_data/Metadata/global-metadata.dat";
/// Relative path to the Windows IL2CPP binary.
pub const BINARY_REL: &str = "GameAssembly.dll";
/// Default output directory name.
pub const OUT_DIR: &str = ".dump";
/// Name of the rebuilt metadata file.
pub const DEC_NAME: &str = "global-metadata.decrypted.dat";

/// Return the metadata path for a game root.
pub fn metadata_path(game_dir: &Path) -> PathBuf {
    game_dir.join(METADATA_REL)
}

/// Return the GameAssembly path for a game root.
pub fn binary_path(game_dir: &Path) -> PathBuf {
    game_dir.join(BINARY_REL)
}

/// Resolve and create the output directory.
pub fn output_path(game_dir: &Path, override_path: Option<&Path>) -> Result<PathBuf, Error> {
    let path = override_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| game_dir.join(OUT_DIR));
    fs::create_dir_all(&path).map_err(|source| io_error(&path, source))?;
    Ok(path)
}

/// Find a game root by checking an explicit environment path and then walking
/// upward from the supplied starting directories.
pub fn find_game_dir(env_game: Option<&Path>, starts: &[PathBuf]) -> PathBuf {
    if let Some(path) = env_game {
        if binary_path(path).exists() {
            return canonical_or_original(path);
        }
    }

    for start in starts {
        let mut current = canonical_or_original(start);
        for _ in 0..6 {
            if binary_path(&current).exists() || current.join("Aniimo_Data").is_dir() {
                return current;
            }
            let Some(parent) = current.parent() else {
                break;
            };
            if parent == current {
                break;
            }
            current = parent.to_path_buf();
        }
    }

    starts
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Resolve the default game root using `APIIMO_GAME` and the current working
/// directory. A library caller that has a script location should prefer
/// [`find_game_dir`] with both starting paths explicitly supplied.
pub fn default_game_dir() -> PathBuf {
    let env_game = env::var_os("APIIMO_GAME").map(PathBuf::from);
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    find_game_dir(env_game.as_deref(), &[cwd])
}

fn canonical_or_original(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
