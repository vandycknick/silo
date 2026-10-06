use crate::{invalid, ConversionError};
use silod_spec::daemon::v1 as w;
pub fn definition_to_wire(
    v: &libvm::NetworkDefinition,
) -> Result<w::NetworkDefinition, ConversionError> {
    Ok(w::NetworkDefinition {
        name: v.name.clone(),
        topology: match v.topology {
            libvm::NetworkTopology::Nat => 1,
            libvm::NetworkTopology::Bridge => 2,
            libvm::NetworkTopology::Isolated => 3,
            _ => return Err(invalid("network.topology", "unsupported native variant")),
        },
        driver: match v.driver {
            libvm::NetworkDriver::Auto => 1,
            libvm::NetworkDriver::Netd => 2,
            _ => return Err(invalid("network.driver", "unsupported native variant")),
        },
    })
}
pub fn definition_from_wire(
    v: w::NetworkDefinition,
) -> Result<libvm::NetworkDefinition, ConversionError> {
    let out = libvm::NetworkDefinition::new(
        v.name,
        match v.topology {
            1 => libvm::NetworkTopology::Nat,
            2 => libvm::NetworkTopology::Bridge,
            3 => libvm::NetworkTopology::Isolated,
            _ => return Err(invalid("network.topology", "invalid enum")),
        },
    )
    .driver(match v.driver {
        1 => libvm::NetworkDriver::Auto,
        2 => libvm::NetworkDriver::Netd,
        _ => return Err(invalid("network.driver", "invalid enum")),
    });
    out.validate()
        .map_err(|_| invalid("network.name", "invalid name"))?;
    Ok(out)
}
