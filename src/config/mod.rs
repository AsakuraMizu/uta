//! Configuration: `uta.toml`, read once when the daemon starts, and the rules
//! file.

pub mod rules;

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub singbox: SingBox,
    pub ports: Ports,
    pub kernel: Kernel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingBox {
    /// The executable; a bare name is looked up in `PATH`.
    pub binary: PathBuf,
    /// Configuration files and directories, merged in this order after uta's
    /// own fragment.
    pub config: Vec<PathBuf>,
    /// The working directory of sing-box, against which relative paths in its
    /// configuration resolve: the directory of `uta.toml`.
    pub work_dir: PathBuf,
}

/// Ports of the inbounds uta adds to sing-box.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ports {
    pub tproxy: u16,
    pub dns: u16,
}

impl Default for Ports {
    fn default() -> Self {
        Self {
            tproxy: 7893,
            dns: 7853,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kernel {
    pub marks: Marks,
    pub route_table: u32,
    /// The first of the four consecutive `ip rule` priorities uta uses.
    pub rule_priority: u32,
    /// The conntrack zone of DNS queries to this host that uta redirects.
    pub conntrack_zone: u16,
}

/// Packet and conntrack mark values, all within a two-bit mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Marks {
    /// The bits uta owns in packet and conntrack marks. The full mask is also
    /// the packet mark of sing-box's own sockets and the conntrack mark of DNS
    /// queries redirected to uta's DNS inbound.
    pub mask: u32,
    /// Captured local traffic: the lower bit of the mask.
    pub local: u32,
    /// Captured forwarded traffic: the higher bit of the mask.
    pub forward: u32,
}

impl Marks {
    fn from_mask(mask: u32) -> Result<Self> {
        ensure!(
            mask.count_ones() == 2,
            "kernel.mark_mask must have exactly two bits set, got {mask:#x}"
        );
        let local = 1 << mask.trailing_zeros();
        Ok(Self {
            mask,
            local,
            forward: mask & !local,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    singbox: RawSingBox,
    #[serde(default)]
    ports: Ports,
    #[serde(default)]
    kernel: RawKernel,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSingBox {
    #[serde(default = "default_binary")]
    binary: PathBuf,
    config: Vec<PathBuf>,
}

fn default_binary() -> PathBuf {
    "sing-box".into()
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawKernel {
    mark_mask: u32,
    route_table: u32,
    rule_priority: u32,
    conntrack_zone: u16,
}

impl Default for RawKernel {
    fn default() -> Self {
        Self {
            mark_mask: 0x3000,
            route_table: 7500,
            rule_priority: 5200,
            conntrack_zone: 7500,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let base = std::path::absolute(path.parent().unwrap_or(Path::new(".")))?;
        let base = base.as_path();
        Self::parse(&text, base).with_context(|| format!("invalid {}", path.display()))
    }

    /// Parses `text`, resolving relative paths against `base`.
    fn parse(text: &str, base: &Path) -> Result<Self> {
        let raw: RawConfig = toml::from_str(text)?;

        ensure!(!raw.singbox.config.is_empty(), "singbox.config is empty");
        // A bare command name is left for `PATH` lookup; anything with a
        // directory is a path.
        let binary = if raw.singbox.binary.components().count() > 1 {
            base.join(&raw.singbox.binary)
        } else {
            raw.singbox.binary
        };
        let config = raw
            .singbox
            .config
            .iter()
            .map(|path| base.join(path))
            .collect();

        ensure!(
            raw.ports.tproxy != 0 && raw.ports.dns != 0,
            "ports.tproxy and ports.dns must be between 1 and 65535"
        );
        ensure!(
            raw.ports.tproxy != raw.ports.dns,
            "ports.tproxy and ports.dns are both {}",
            raw.ports.dns
        );

        let kernel = raw.kernel;
        // 0 is unspecified; 253 to 255 are the default, main and local tables.
        ensure!(
            !matches!(kernel.route_table, 0 | 253..=255),
            "kernel.route_table {} is reserved",
            kernel.route_table
        );
        ensure!(
            (1..=u32::MAX - 3).contains(&kernel.rule_priority),
            "kernel.rule_priority must be between 1 and {}",
            u32::MAX - 3
        );
        ensure!(
            kernel.conntrack_zone != 0,
            "kernel.conntrack_zone 0 is the default zone"
        );

        Ok(Self {
            singbox: SingBox {
                binary,
                config,
                work_dir: base.to_path_buf(),
            },
            ports: raw.ports,
            kernel: Kernel {
                marks: Marks::from_mask(kernel.mark_mask)?,
                route_table: kernel.route_table,
                rule_priority: kernel.rule_priority,
                conntrack_zone: kernel.conntrack_zone,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config> {
        Config::parse(text, Path::new("/etc/uta"))
    }

    fn error(text: &str) -> String {
        format!("{:#}", parse(text).unwrap_err())
    }

    #[test]
    fn minimal_config_uses_defaults_and_resolves_paths() {
        let config = parse("[singbox]\nconfig = [\"sing-box\", \"/srv/extra.json\"]\n").unwrap();
        assert_eq!(config.singbox.binary, Path::new("sing-box"));
        assert_eq!(
            config.singbox.config,
            [Path::new("/etc/uta/sing-box"), Path::new("/srv/extra.json")]
        );
        assert_eq!(config.ports, Ports::default());
        assert_eq!(
            config.kernel.marks,
            Marks {
                mask: 0x3000,
                local: 0x1000,
                forward: 0x2000
            }
        );
    }

    #[test]
    fn binary_with_a_directory_is_resolved() {
        let config = parse("[singbox]\nbinary = \"bin/sing-box\"\nconfig = [\"c\"]\n").unwrap();
        assert_eq!(config.singbox.binary, Path::new("/etc/uta/bin/sing-box"));
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(error("[singbox]\nconfig = [\"c\"]\nlisten = 1\n").contains("unknown field"));
    }

    #[test]
    fn rejects_inconsistent_values() {
        let with = |extra: &str| error(&format!("[singbox]\nconfig = [\"c\"]\n{extra}"));
        assert_eq!(
            with("[kernel]\nmark_mask = 0x7000\n"),
            "kernel.mark_mask must have exactly two bits set, got 0x7000"
        );
        assert_eq!(
            with("[ports]\ntproxy = 53\ndns = 53\n"),
            "ports.tproxy and ports.dns are both 53"
        );
        assert_eq!(
            with("[ports]\ndns = 0\n"),
            "ports.tproxy and ports.dns must be between 1 and 65535"
        );
        assert_eq!(
            with("[kernel]\nroute_table = 254\n"),
            "kernel.route_table 254 is reserved"
        );
        assert_eq!(
            with("[kernel]\nconntrack_zone = 0\n"),
            "kernel.conntrack_zone 0 is the default zone"
        );
        assert_eq!(error("[singbox]\nconfig = []\n"), "singbox.config is empty");
    }

    #[test]
    fn marks_split_a_non_contiguous_mask() {
        let config = parse("[singbox]\nconfig = [\"c\"]\n[kernel]\nmark_mask = 0x10001\n").unwrap();
        assert_eq!(config.kernel.marks.local, 0x1);
        assert_eq!(config.kernel.marks.forward, 0x10000);
    }
}
