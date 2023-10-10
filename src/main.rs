use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};

#[derive(Debug)]
pub struct OidTreeEntry {
    id: u64,
    value: u32,
    parent: Option<u64>,
    name: Option<String>,
    root: bool,
}

#[derive(Debug)]
pub struct OidTree {
    next_id: u64,
    nodes: Vec<OidTreeEntry>,
}

#[derive(Debug, PartialEq)]
pub enum IfOperStatus {
    Up,
    Down,
    Testing,
    Unknown,
    Dormant,
    NotPresent,
    LowerLayerDown,
}

impl TryFrom<csnmp::ObjectValue> for IfOperStatus {
    type Error = anyhow::Error;

    fn try_from(
        value: csnmp::ObjectValue,
    ) -> std::result::Result<Self, Self::Error> {
        if !value.is_integer() {
            bail!("not an integer");
        }

        Ok(if let Some(val) = value.as_i32() {
            match val {
                1 => IfOperStatus::Up,
                2 => IfOperStatus::Down,
                3 => IfOperStatus::Testing,
                4 => IfOperStatus::Unknown,
                5 => IfOperStatus::Dormant,
                6 => IfOperStatus::NotPresent,
                7 => IfOperStatus::LowerLayerDown,
                other => bail!("invalid value {other}"),
            }
        } else {
            bail!("not an integer in the expected range");
        })
    }
}

#[derive(Debug)]
pub enum IfAdminStatus {
    Up,
    Down,
    Testing,
}

impl TryFrom<csnmp::ObjectValue> for IfAdminStatus {
    type Error = anyhow::Error;

    fn try_from(
        value: csnmp::ObjectValue,
    ) -> std::result::Result<Self, Self::Error> {
        if !value.is_integer() {
            bail!("not an integer");
        }

        Ok(if let Some(val) = value.as_i32() {
            match val {
                1 => IfAdminStatus::Up,
                2 => IfAdminStatus::Down,
                3 => IfAdminStatus::Testing,
                other => bail!("invalid value {other}"),
            }
        } else {
            bail!("not an integer in the expected range");
        })
    }
}

#[derive(Debug)]
pub enum IfType {
    EthernetCsmacd,
    SoftwareLoopback,
    PropPointToPointSerial,
    Other,
    Unknown(i32),
}

impl TryFrom<csnmp::ObjectValue> for IfType {
    type Error = anyhow::Error;

    fn try_from(
        value: csnmp::ObjectValue,
    ) -> std::result::Result<Self, Self::Error> {
        if !value.is_integer() {
            bail!("not an integer");
        }

        Ok(if let Some(val) = value.as_i32() {
            match val {
                1 => IfType::Other,
                6 => IfType::EthernetCsmacd,
                22 => IfType::PropPointToPointSerial,
                24 => IfType::SoftwareLoopback,
                n => IfType::Unknown(n),
            }
        } else {
            bail!("not an integer in the expected range");
        })
    }
}

impl OidTree {
    fn new() -> OidTree {
        OidTree { next_id: 1000, nodes: Default::default() }
    }

    pub fn oid_by_name(&self, name: &str) -> Result<Vec<u32>> {
        let t = name.split(".").collect::<Vec<_>>();
        if t.is_empty() {
            bail!("what?")
        }

        /*
         * First, find a root entry in the tree with this name:
         */
        let root = self
            .nodes
            .iter()
            .find(|n| n.root && n.name.as_deref() == Some(t[0]));
        let Some(root) = root else {
            bail!("could not find root node {:?}", t[0]);
        };

        /*
         * Now, walk down the tree we've been provided and match nodes.
         */
        let mut prior = root;
        for &tt in t.iter().skip(1) {
            let next = self.nodes.iter().find(|n| {
                !n.root
                    && n.name.as_deref() == Some(tt)
                    && n.parent == Some(prior.id)
            });

            if let Some(next) = next {
                prior = next;
            } else {
                bail!("could not find {tt:?}");
            }
        }

        /*
         * Make the numeric oid by walking back up:
         */
        let mut out = Vec::new();
        loop {
            out.push(prior.value);
            if let Some(next) = prior.parent {
                prior = self.nodes.iter().find(|n| n.id == next).unwrap();
            } else {
                break;
            }
        }

        out.reverse();
        Ok(out)
    }

    pub fn oid_name(&self, oid: &[u32]) -> Result<String> {
        /*
         * Try to find an oid entry for this oid.
         */
        let mut n = oid.len();
        let mut out = Vec::new();
        let mut anchor = loop {
            if n == 0 {
                /*
                 * We give up.
                 */
                bail!("cannot do it");
            }

            if let Ok(ent) = self.find_oid(&oid[0..n]) {
                /*
                 * Found an anchor!
                 */
                break ent;
            } else {
                out.push(oid[n - 1].to_string());
                n -= 1;
            }
        };

        loop {
            if let Some(name) = anchor.name.as_deref() {
                out.push(name.to_string());
            } else {
                out.push(anchor.value.to_string());
            }

            if anchor.root {
                break;
            }

            if let Some(parent) = anchor.parent {
                anchor = self.nodes.iter().find(|n| n.id == parent).unwrap();
            } else {
                break;
            }
        }

        out.reverse();
        Ok(out.join("."))
    }

    fn find_oid(&self, oid: &[u32]) -> Result<&OidTreeEntry> {
        let mut prior = None;
        for &e in oid {
            let next =
                self.nodes.iter().find(|n| n.parent == prior && n.value == e);

            prior = Some(if let Some(next) = next {
                next.id
            } else {
                bail!("could not find oid {oid:?}");
            });
        }
        Ok(self.nodes.iter().find(|n| n.id == prior.unwrap()).unwrap())
    }

    fn find_oid_mut(&mut self, oid: &[u32]) -> Result<&mut OidTreeEntry> {
        let mut prior = None;
        for &e in oid {
            let next =
                self.nodes.iter().find(|n| n.parent == prior && n.value == e);

            prior = Some(if let Some(next) = next {
                next.id
            } else {
                bail!("could not find oid {oid:?}");
            });
        }
        Ok(self.nodes.iter_mut().find(|n| n.id == prior.unwrap()).unwrap())
    }

    pub fn add_oid_under(
        &mut self,
        parent: &[u32],
        oid: &[u32],
        name: &str,
    ) -> Result<Vec<u32>> {
        if oid.is_empty() || name.is_empty() {
            bail!("that wont work");
        }

        /*
         * Populate down the tree to the node we want to name.
         */
        let mut prior = Some(self.find_oid(parent)?.id);
        for &e in oid {
            let next = self
                .nodes
                .iter_mut()
                .find(|n| n.parent == prior && n.value == e);

            prior = Some(if let Some(next) = next {
                next.id
            } else {
                let id = self.next_id;
                self.next_id += 1;

                self.nodes.push(OidTreeEntry {
                    id,
                    value: e,
                    parent: prior,
                    name: None,
                    root: false,
                });
                id
            });
        }

        /*
         * Now that we're sure everything is there, locate the right node.
         */
        let mut full_oid = parent.to_vec();
        full_oid.extend(oid.to_vec());

        let ent = self.find_oid_mut(&full_oid).unwrap();
        ent.root = false;
        ent.name = Some(name.to_string());

        Ok(full_oid)
    }

    pub fn add_oid_root(
        &mut self,
        oid: &[u32],
        name: &str,
    ) -> Result<Vec<u32>> {
        if oid.is_empty() || name.is_empty() {
            bail!("that wont work");
        }

        /*
         * Populate down the tree to the node we want to name.
         */
        let mut prior = None;
        for &e in oid {
            let next = self
                .nodes
                .iter_mut()
                .find(|n| n.parent == prior && n.value == e);

            prior = Some(if let Some(next) = next {
                next.id
            } else {
                let id = self.next_id;
                self.next_id += 1;

                self.nodes.push(OidTreeEntry {
                    id,
                    value: e,
                    parent: prior,
                    name: None,
                    root: false,
                });
                id
            });
        }

        /*
         * Now that we're sure everything is there, locate the right node.
         */
        let ent = self.find_oid_mut(oid).unwrap();
        ent.root = true;
        ent.name = Some(name.to_string());

        Ok(oid.to_vec())
    }
}

fn populate_mib() -> Result<OidTree> {
    let mut tree = OidTree::new();
    let internet = tree.add_oid_root(&[1, 3, 6, 1], "internet")?;
    let mgmt = tree.add_oid_under(&internet, &[2], "mgmt")?;
    let mib_2 = tree.add_oid_under(&mgmt, &[1], "mib-2")?;
    let interfaces = tree.add_oid_under(&mib_2, &[2], "interfaces")?;
    #[allow(unused)]
    let if_number = tree.add_oid_under(&interfaces, &[1], "ifNumber")?;
    let if_table = tree.add_oid_under(&interfaces, &[2], "ifTable")?;
    let if_entry = tree.add_oid_under(&if_table, &[1], "ifEntry")?;

    for (idx, entry_name) in [
        "ifIndex",
        "ifDescr",
        "ifType",
        "ifMtu",
        "ifSpeed",
        "ifPhysAddress",
        "ifAdminStatus",
        "ifOperStatus",
        "ifLastChange",
        "ifInOctets",
        "ifInUcastPkts",
        "ifInNUcastPkts",
        "ifInDiscards",
        "ifInErrors",
        "ifInUnknownProtos",
        "ifOutOctets",
        "ifOutUcastPkts",
        "ifOutNUcastPkts",
        "ifOutDiscards",
        "ifOutErrors",
        "ifOutQLen",
        "ifSpecific",
    ]
    .iter()
    .enumerate()
    {
        let idx: u32 = idx.try_into().unwrap();
        tree.add_oid_under(&if_entry, &[idx + 1], entry_name)?;
    }

    let private = tree.add_oid_under(&internet, &[4], "private")?;
    let enterprises = tree.add_oid_under(&private, &[1], "enterprises")?;

    /*
     * Cisco bullshit:
     */
    let switch001 =
        tree.add_oid_under(&enterprises, &[9, 6, 1, 101], "switch001")?;
    let sw_interfaces =
        tree.add_oid_under(&switch001, &[43], "swInterfaces")?;
    let sw_if_table = tree.add_oid_under(&sw_interfaces, &[1], "swIfTable")?;
    let sw_if_entry = tree.add_oid_under(&sw_if_table, &[1], "swIfTable")?;

    for (idx, entry_name) in [
        "swIfIndex",
        "swIfPhysAddressType",
        "swIfDuplexAdminMode",
        "swIfDuplexOperMode",
        "swIfBackPressureMode",
        "swIfTaggedMode",
        "swIfTransceiverType",
        "swIfLockAdminStatus",
        "swIfLockOperStatus",
        "swIfType",
        "swIfDefaultTag",
        "swIfDefaultPriority",
        "swIfAdminStatus",
        "swIfFlowControlMode",
        "swIfSpeedAdminMode",
        "swIfSpeedDuplexAutoNegotiation",
        "swIfOperFlowControlMode",
        "swIfOperSpeedDuplexAutoNegotiation",
        "swIfOperBackPressureMode",
        "swIfAdminLockAction",
        "swIfOperLockAction",
        "swIfAdminLockTrapEnable",
        "swIfOperLockTrapEnable",
        "swIfOperSuspendedStatus",
        "swIfLockOperTrapCount",
        "swIfLockAdminTrapFrequency",
        "swIfReActivate",
        "swIfAdminMdix",
        "swIfOperMdix",
        "swIfHostMode",
        "swIfSingleHostViolationAdminAction",
        "swIfSingleHostViolationOperAction",
        "swIfSingleHostViolationAdminTrapEnable",
        "swIfSingleHostViolationOperTrapEnable",
        "swIfSingleHostViolationOperTrapCount",
        "swIfSingleHostViolationAdminTrapFrequency",
        "swIfLockLimitationMode",
        "swIfLockMaxMacAddresses",
        "swIfLockMacAddressesCount",
        "swIfAdminSpeedDuplexAutoNegotiationLocalCapabilities",
        "swIfOperSpeedDuplexAutoNegotiationLocalCapabilities",
        "swIfSpeedDuplexNegotiationRemoteCapabilities",
        "swIfAdminComboMode",
        "swIfOperComboMode",
        "swIfAutoNegotiationMasterSlavePreference",
        "swIfPortCapabilities",
        "swIfPortStateDuration",
        "swIfApNegotiationLane",
        "swIfPortFecMode",
        "swIfPortNumOfLanes",
    ]
    .iter()
    .enumerate()
    {
        let idx: u32 = idx.try_into().unwrap();
        tree.add_oid_under(&sw_if_entry, &[idx + 1], entry_name)?;
    }

    Ok(tree)
}

#[tokio::main]
async fn main() -> Result<()> {
    let a = getopts::Options::new()
        .optflag("v", "", "verbose output")
        .parsing_style(getopts::ParsingStyle::StopAtFirstFree)
        .parse(std::env::args().skip(1))?;

    if a.free.len() != 1 {
        bail!("IP address of switch?");
    }

    let verbose = a.opt_present("v");

    let addr: std::net::IpAddr = a.free[0].parse()?;
    println!("using switch address {addr}");

    let bind = match &addr {
        std::net::IpAddr::V4(_) => "0.0.0.0:0",
        std::net::IpAddr::V6(_) => "[::]:0",
    };

    let tree = populate_mib()?;

    /*
     * We want the interface table:
     */
    let top_oid = csnmp::ObjectIdentifier::try_from(
        tree.oid_by_name("internet.mgmt.mib-2.interfaces.ifTable")?.as_slice(),
    )?;
    let name = tree.oid_name(top_oid.as_slice())?;

    /*
     * We also want to be able to identify specific entries from within the
     * table by prefix:
     */
    let if_type = csnmp::ObjectIdentifier::try_from(
        tree.oid_by_name(
            "internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifType",
        )?
        .as_slice(),
    )?;
    let if_oper_status = csnmp::ObjectIdentifier::try_from(
        tree.oid_by_name(
            "internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifOperStatus",
        )?
        .as_slice(),
    )?;
    let if_descr = csnmp::ObjectIdentifier::try_from(
        tree.oid_by_name(
            "internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifDescr",
        )?
        .as_slice(),
    )?;

    println!("top oid = {name:?} -> {top_oid}");

    println!("creating client...");
    let c = csnmp::Snmp2cClient::new(
        std::net::SocketAddr::new(addr, 161),
        b"muppets".to_vec(),
        Some(bind.parse()?),
        Some(Duration::from_secs(5)),
    )
    .await?;

    println!("walking from {name:?} ({top_oid}) ...");

    fn blank_map() -> BTreeMap<u32, Option<IfOperStatus>> {
        (1u32..=16).map(|port| (port, None)).collect()
    }

    let mut oldmap = blank_map();

    loop {
        let start = Instant::now();
        let res = c.walk_bulk(top_oid, 0, 63).await?;
        let mut link_states: BTreeMap<u32, IfOperStatus> = Default::default();
        let mut link_desc: BTreeMap<u32, String> = Default::default();
        let mut link_types: BTreeMap<u32, IfType> = Default::default();
        for (oid, val) in res {
            if let Some(rel) = oid.relative_to(&if_type) {
                let idx = rel.as_slice()[0];
                let ift = IfType::try_from(val)?;
                link_types.insert(idx, ift);
            } else if let Some(rel) = oid.relative_to(&if_oper_status) {
                let idx = rel.as_slice()[0];
                let ifs = IfOperStatus::try_from(val)?;
                link_states.insert(idx, ifs);
            } else if let Some(rel) = oid.relative_to(&if_descr) {
                let idx = rel.as_slice()[0];
                link_desc.insert(
                    idx,
                    String::from_utf8_lossy(val.as_bytes().unwrap())
                        .to_string(),
                );
            }
        }

        /*
         * We only care about the copper gigabit ports right now.  Start with an
         * unknown state for each of them:
         */
        let mut map = blank_map();

        /*
         * Look at what we actually got back from the switch and update the map.
         */
        if verbose {
            println!("{:<20} {}", "PORT", "STATE");
        }
        for (idx, st) in link_states {
            let Some(desc) = link_desc.get(&idx) else { continue; };
            let Some(ltype) = link_types.get(&idx) else { continue; };

            if !matches!(ltype, IfType::EthernetCsmacd) {
                continue;
            }

            let Some(port) = desc.strip_prefix("GigabitEthernet") else {
                continue;
            };
            let Ok(port) = port.parse::<u32>() else { continue; };

            if verbose {
                println!("{:<20} {:?}", desc, st);
            }

            map.insert(port, Some(st));
        }

        if verbose {
            println!("{map:#?}");

            let delta =
                Instant::now().saturating_duration_since(start).as_millis();
            println!("    (took {delta}ms)");
            println!();
        }

        let mut banner = false;

        for port in 1u32..=16 {
            let old = oldmap.get(&port).unwrap();
            let new = map.get(&port).unwrap();

            if old != new {
                if !banner {
                    println!("-------------------------");
                    banner = true;
                }

                println!("{port:<2} {old:?} -> {new:?}");
            }
        }

        oldmap = map;

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
