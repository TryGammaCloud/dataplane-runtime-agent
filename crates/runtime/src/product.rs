//! Validate build-time product identity without treating it as attestation.
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Legacy,
    Sandbox,
    Models,
}

impl Product {
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        match raw.trim() {
            "legacy" => Ok(Self::Legacy),
            "sandbox" => Ok(Self::Sandbox),
            "models" => Ok(Self::Models),
            _ => Err("invalid-product-profile"),
        }
    }

    pub fn allows_workload(self) -> bool {
        matches!(self, Self::Legacy | Self::Sandbox)
    }
}

/// A missing profile is legacy for compatibility with existing development guests.
/// An invalid or unreadable configured profile fails closed.
pub fn load() -> std::io::Result<Product> {
    let path = std::env::var("GAMMACLOUD_PRODUCT_PROFILE_FILE")
        .unwrap_or_else(|_| "/etc/gammacloud/profile".into());
    match std::fs::read_to_string(Path::new(&path)) {
        Ok(value) => Product::parse(&value)
            .map_err(|reason| std::io::Error::new(std::io::ErrorKind::InvalidData, reason)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
            && std::env::var_os("GAMMACLOUD_PRODUCT_PROFILE_FILE").is_none() => Ok(Product::Legacy),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiles_are_explicit_and_fail_closed() {
        assert_eq!(Product::parse("sandbox\n").unwrap(), Product::Sandbox);
        assert_eq!(Product::parse("models\n").unwrap(), Product::Models);
        assert!(Product::parse("models extra").is_err());
        assert!(Product::Sandbox.allows_workload());
        assert!(!Product::Models.allows_workload());
    }
}
