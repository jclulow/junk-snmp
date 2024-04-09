use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};

pub mod apc;
pub mod cisco;

use crate::oidtree::OidTree;

pub fn populate_base() -> Result<OidTree> {
    let mut tree = OidTree::new();

    let internet = tree.add_oid_root(&[1, 3, 6, 1], "internet")?;
    add_from_instructions_under(
        &mut tree,
        "internet",
        internet,
        &[
            ("mgmt", "internet", 2),
            ("private", "internet", 4),
            ("enterprises", "private", 1),
        ],
    )
    .map_err(|e| anyhow!("populate_base: {e}"))?;

    Ok(tree)
}

pub fn populate_mib2(tree: &mut OidTree) -> Result<()> {
    add_from_instructions_under(
        tree,
        "mgmt",
        tree.oid_by_name("internet.mgmt")?.as_slice().to_vec(),
        &[
            ("mib-2", "mgmt", 1),
            ("interfaces", "mib-2", 2),
            ("ifNumber", "interfaces", 1),
            ("ifTable", "interfaces", 2),
            ("ifEntry", "ifTable", 1),
            ("ifIndex", "ifEntry", 1),
            ("ifDescr", "ifEntry", 2),
            ("ifType", "ifEntry", 3),
            ("ifMtu", "ifEntry", 4),
            ("ifSpeed", "ifEntry", 5),
            ("ifPhysAddress", "ifEntry", 6),
            ("ifAdminStatus", "ifEntry", 7),
            ("ifOperStatus", "ifEntry", 8),
            ("ifLastChange", "ifEntry", 9),
            ("ifInOctets", "ifEntry", 10),
            ("ifInUcastPkts", "ifEntry", 11),
            ("ifInNUcastPkts", "ifEntry", 12),
            ("ifInDiscards", "ifEntry", 13),
            ("ifInErrors", "ifEntry", 14),
            ("ifInUnknownProtos", "ifEntry", 15),
            ("ifOutOctets", "ifEntry", 16),
            ("ifOutUcastPkts", "ifEntry", 17),
            ("ifOutNUcastPkts", "ifEntry", 18),
            ("ifOutDiscards", "ifEntry", 19),
            ("ifOutErrors", "ifEntry", 20),
            ("ifOutQLen", "ifEntry", 21),
            ("ifSpecific", "ifEntry", 22),
        ],
    )
    .map_err(|e| anyhow!("populate_mib2: {e}"))?;

    Ok(())
}

fn add_from_instructions_under(
    tree: &mut OidTree,
    anchor_name: &str,
    anchor_oid: Vec<u32>,
    instructions: &[(&str, &str, u32)],
) -> Result<()> {
    let mut seen: HashMap<&str, Vec<u32>> = Default::default();
    seen.insert(anchor_name, anchor_oid);

    for (ins, under, rel) in instructions {
        if let Some(under) = seen.get(under).cloned() {
            let new = tree.add_oid_under(&under, &[*rel], ins)?;
            if seen.insert(ins, new).is_some() {
                bail!("adding: duplicate? {ins:?} -> {{ {under:?} {rel} }}");
            }
        } else {
            bail!("adding: could not find {{ {under:?} {rel} }} for {ins:?}");
        }
    }

    Ok(())
}
