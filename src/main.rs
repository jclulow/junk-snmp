use std::{
    collections::{BTreeMap, HashMap},
    ops::Bound,
    result::Result as SResult,
    time::Duration,
};

use anyhow::{bail, Result};
use csnmp::{ObjectIdentifier, ObjectValue};
use serde::de::{Error, Unexpected};
use serde::Deserialize;
use serde::{de::value::MapDeserializer, Deserializer};
use serde_repr::Deserialize_repr;

pub mod mib;
pub mod oidtree;

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

    fn try_from(value: csnmp::ObjectValue) -> SResult<Self, Self::Error> {
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

    fn try_from(value: csnmp::ObjectValue) -> SResult<Self, Self::Error> {
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

    fn try_from(value: csnmp::ObjectValue) -> SResult<Self, Self::Error> {
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

fn populate_mib() -> Result<oidtree::OidTree> {
    let mut tree = mib::populate_base()?;

    mib::populate_mib2(&mut tree)?;
    mib::cisco::populate(&mut tree)?;
    mib::apc::populate(&mut tree)?;

    Ok(tree)
}

struct ObjectValueWrap(ObjectValue);

impl<'de> serde::de::IntoDeserializer<'de> for ObjectValueWrap {
    type Deserializer = ObjectValueDeserializer;

    fn into_deserializer(self) -> Self::Deserializer {
        ObjectValueDeserializer(self.0.clone())
    }
}

struct ObjectValueDeserializer(ObjectValue);

impl ObjectValueDeserializer {
    fn as_u64(&self) -> SResult<u64, serde::de::value::Error> {
        match &self.0 {
            ObjectValue::Integer(i) => {
                if *i < 0 {
                    Err(serde::de::value::Error::invalid_value(
                        Unexpected::Signed(*i as i64),
                        &"a u32",
                    ))
                } else {
                    Ok((*i).try_into().unwrap())
                }
            }

            ObjectValue::Counter32(u)
            | ObjectValue::Unsigned32(u)
            | ObjectValue::TimeTicks(u) => Ok((*u).into()),

            ObjectValue::Counter64(u) => Ok(*u),

            _ => Err(serde::de::value::Error::invalid_value(
                Unexpected::Other("other SNMP type"),
                &"a u64",
            )),
        }
    }

    fn as_i64(&self) -> SResult<i64, serde::de::value::Error> {
        match &self.0 {
            ObjectValue::Integer(i) => Ok((*i).into()),

            ObjectValue::Counter32(u)
            | ObjectValue::Unsigned32(u)
            | ObjectValue::TimeTicks(u) => Ok((*u).into()),

            ObjectValue::Counter64(u) => {
                let v: i64 = (*u).try_into().map_err(|_| {
                    serde::de::value::Error::invalid_value(
                        Unexpected::Unsigned(*u),
                        &"an i64",
                    )
                })?;

                Ok(v)
            }

            _ => Err(serde::de::value::Error::invalid_value(
                Unexpected::Other("other SNMP type"),
                &"an i64",
            )),
        }
    }
}

impl<'de> Deserializer<'de> for ObjectValueDeserializer {
    type Error = serde::de::value::Error;

    fn deserialize_any<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        match &self.0 {
            ObjectValue::Integer(_) => self.deserialize_i32(v),
            ObjectValue::String(_) => self.deserialize_str(v),
            ObjectValue::ObjectId(_) => self.deserialize_seq(v),
            ObjectValue::Counter32(_)
            | ObjectValue::Unsigned32(_)
            | ObjectValue::TimeTicks(_) => self.deserialize_u32(v),
            ObjectValue::Counter64(_) => self.deserialize_u64(v),
            ObjectValue::IpAddress(_) | ObjectValue::Opaque(_) => {
                self.deserialize_bytes(v)
            }
        }
    }

    fn deserialize_bool<V>(self, _v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no bool support"))
    }

    fn deserialize_i8<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_i64(v)
    }

    fn deserialize_i16<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_i64(v)
    }

    fn deserialize_i32<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_i64(v)
    }

    fn deserialize_i64<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        v.visit_i64(self.as_i64()?)
    }

    fn deserialize_u8<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_u64(v)
    }

    fn deserialize_u16<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_u64(v)
    }

    fn deserialize_u32<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_u64(v)
    }

    fn deserialize_u64<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        v.visit_u64(self.as_u64()?)
    }

    fn deserialize_f32<V>(self, _v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no f32 support"))
    }

    fn deserialize_f64<V>(self, _v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no f64 support"))
    }

    fn deserialize_char<V>(self, _v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no char support"))
    }

    fn deserialize_str<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        match &self.0 {
            ObjectValue::String(buf) => {
                v.visit_str(std::str::from_utf8(buf).map_err(|_| {
                    serde::de::value::Error::invalid_value(
                        Unexpected::Bytes(buf),
                        &"a valid UTF-8 string",
                    )
                })?)
            }
            _ => Err(serde::de::value::Error::invalid_value(
                Unexpected::Other("other SNMP value"),
                &"a valid UTF-8 string",
            )),
        }
    }

    fn deserialize_string<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_str(v)
    }

    fn deserialize_bytes<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        match &self.0 {
            ObjectValue::String(buf) | ObjectValue::Opaque(buf) => {
                v.visit_bytes(buf)
            }
            _ => Err(serde::de::value::Error::invalid_value(
                Unexpected::Other("other SNMP value"),
                &"an opaque or a string",
            )),
        }
    }

    fn deserialize_byte_buf<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_bytes(v)
    }

    fn deserialize_option<V>(self, _v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no option support"))
    }

    fn deserialize_unit<V>(self, _v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no unit support"))
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        _v: V,
    ) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no unit struct support"))
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        _v: V,
    ) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no newtype struct support"))
    }

    fn deserialize_seq<V>(self, _v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no seq support"))
    }

    fn deserialize_tuple<V>(
        self,
        _len: usize,
        _v: V,
    ) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no tuple support"))
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _v: V,
    ) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no tuple struct support"))
    }

    fn deserialize_map<V>(self, _v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no map support"))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _v: V,
    ) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no struct support"))
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _v: V,
    ) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no enum support"))
    }

    fn deserialize_identifier<V>(self, _v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(serde::de::value::Error::custom("no identifier support"))
    }

    fn deserialize_ignored_any<V>(self, v: V) -> SResult<V::Value, Self::Error>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_any(v)
    }
}

impl std::fmt::Debug for ObjectValueWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ObjectValue::Integer(i) => format_args!("{}", i).fmt(f),
            ObjectValue::String(vu) => {
                format_args!("{:?}", String::from_utf8_lossy(vu)).fmt(f)
            }
            ObjectValue::ObjectId(oid) => format_args!("<oid:{oid}>").fmt(f),
            ObjectValue::IpAddress(ip) => format_args!("{}", ip).fmt(f),
            ObjectValue::Counter32(u) => format_args!("{}", u).fmt(f),
            ObjectValue::Unsigned32(u) => format_args!("{}", u).fmt(f),
            ObjectValue::TimeTicks(u) => format_args!("{}", u).fmt(f),
            ObjectValue::Opaque(buf) => format_args!("{:?}", buf).fmt(f),
            ObjectValue::Counter64(u) => format_args!("{}", u).fmt(f),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(unused)]
struct Ident {
    index: u32,
    module: u32,
    name: String,
    location: String,
    hardware_rev: String,
    firmware_rev: String,
    date_of_manufacture: String,
    model_number: String,
    serial_number: String,
    contact: String,
    boot_monitor_rev: String,
    long_description: String,
    #[serde(rename = "NMCSerialNumber")]
    nmc_serial_number: String,
    app_build_date: String,
    #[serde(rename = "AOSBuildDate")]
    aos_build_date: String,
    boot_mon_build_date: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(unused)]
struct BankConfiguration {
    index: u32,
    module: u32,
    number: u32,
    overload_restriction: OverloadRestriction,
    low_load_current_threshold: u32,
    near_overload_current_threshold: u32,
    overload_current_threshold: u32,
    bank_peak_current_reset: PeakCurrentReset,
}

#[derive(Deserialize_repr, PartialEq, Eq, Debug)]
#[repr(i32)]
enum OverloadRestriction {
    AlwaysAllowTurnOn = 1,
    RestrictOnNearOverload = 2,
    RestrictOnOverload = 3,
    NotSupported = 4,
}

#[derive(Deserialize_repr, PartialEq, Eq, Debug)]
#[repr(i32)]
enum PeakCurrentReset {
    NoOperation = 1,
    Reset = 2,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(unused)]
struct BankProperties {
    index: u32,
    module: u32,
    number: u32,
    phase_layout: PhaseLayoutType,
    breaker_rating: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(unused)]
struct BankStatus {
    index: u32,
    module: u32,
    number: u32,
    load_state: LoadState,
    current: u32,
    peak_current: u32,
    peak_current_timestamp: String,
    peak_current_start_time: String,
}

#[derive(Deserialize_repr, PartialEq, Eq, Debug)]
#[repr(i32)]
enum LoadState {
    LowLoad = 1,
    Normal = 2,
    NearOverload = 3,
    Overload = 4,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(unused)]
struct OutletControl {
    index: u32,
    module: u32,
    name: String,
    number: u32,
    command: OutletCommand,
}

#[derive(Deserialize_repr, PartialEq, Eq, Debug)]
#[repr(i32)]
enum OutletCommand {
    ImmediateOn = 1,
    ImmediateOff = 2,
    ImmediateReboot = 3,
    OutletUnknown = 4,
    DelayedOn = 5,
    DelayedOff = 6,
    DelayedReboot = 7,
    CancelPendingCommand = 8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(unused)]
struct OutletConfig {
    index: u32,
    module: u32,
    name: String,
    number: u32,
    power_on_time: i32,
    power_off_time: i32,
    reboot_duration: u32,
    external_link: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(unused)]
struct OutletProperties {
    index: u32,
    module: u32,
    name: String,
    number: u32,

    phase_layout: PhaseLayoutType,
    bank: u32,
}

#[derive(Deserialize_repr, PartialEq, Eq, Debug)]
#[repr(i32)]
enum PhaseLayoutType {
    Phase1ToNeutral = 1,
    Phase2ToNeutral = 2,
    Phase3ToNeutral = 3,
    Phase1ToPhase2 = 4,
    Phase2ToPhase3 = 5,
    Phase3ToPhase1 = 6,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(unused)]
struct OutletStatus {
    index: u32,
    module: u32,
    name: String,
    number: u32,

    state: State,
    command_pending: CommandPending,
    external_link: String,
}

#[derive(Deserialize_repr, PartialEq, Eq, Debug)]
#[repr(i32)]
enum CommandPending {
    Yes = 1,
    No = 2,
    Unknown = 3,
}

#[derive(Deserialize_repr, PartialEq, Eq, Debug)]
#[repr(i32)]
enum State {
    Off = 1,
    On = 2,
}

fn table_entry_range(
    oid: ObjectIdentifier,
) -> (Bound<ObjectIdentifier>, Bound<ObjectIdentifier>) {
    let last_id = *oid.as_slice().iter().last().unwrap();
    let one_after =
        oid.parent().unwrap().child(last_id.checked_add(1).unwrap()).unwrap();
    (std::ops::Bound::Included(oid), std::ops::Bound::Excluded(one_after))
}

fn extract_table<T>(
    tree: &oidtree::OidTree,
    res: &BTreeMap<ObjectIdentifier, ObjectValue>,
    table_size: ObjectIdentifier,
    table_entry: ObjectIdentifier,
    strip_name_prefix: &str,
) -> Result<BTreeMap<u32, T>>
where
    T: for<'de> Deserialize<'de>,
{
    /*
     * Get the size of the table from the results:
     */
    let Some(size) = res.get(&table_size.child(0).unwrap()) else {
        bail!("could not locate table size at {table_size})");
    };

    let size = match size {
        ObjectValue::Integer(i) => {
            if *i < 0 {
                bail!("negative size {i} at {table_size}");
            }

            *i as u32
        }
        other => bail!("invalid size {other:?} at {table_size}"),
    };

    /*
     * Collect entries from the table:
     */
    let mut out: BTreeMap<u32, HashMap<String, ObjectValueWrap>> =
        BTreeMap::new();
    for (oid, val) in res.range(table_entry_range(table_entry)) {
        let rel =
            oid.relative_to(&table_entry).expect("must be a child of oid");
        if rel.len() != 2 || rel.as_slice()[1] == 0 {
            bail!("unusual table structure: {rel} under {oid}?");
        }

        let n = tree.oid_name(&oid.parent().unwrap())?;
        let Some(n) = n.basename().strip_prefix(strip_name_prefix) else {
            bail!("name {n} not prefixed with {strip_name_prefix:?}");
        };

        let i = rel.as_slice()[1];
        let map = out.entry(i).or_default();
        if map.insert(n.to_string(), ObjectValueWrap(val.clone())).is_some() {
            bail!("duplicate {n:?}[{i}] value?");
        }
    }

    for i in 1..=size {
        if !out.contains_key(&i) {
            bail!("table is missing index {i}?");
        }
    }

    /*
     * Deserialise the results!
     */
    Ok(out
        .into_iter()
        .map(|(idx, map)| {
            Ok((idx, T::deserialize(MapDeserializer::new(map.into_iter()))?))
        })
        .collect::<Result<_>>()?)
}

struct RPdu2<'a>(&'a oidtree::OidTree, BTreeMap<ObjectIdentifier, ObjectValue>);

impl<'a> RPdu2<'a> {
    fn top(&'a self) -> Result<ObjectIdentifier> {
        self.0.oid_by_name(
            "internet.private.enterprises.apc.products.hardware.rPDU2",
        )
    }

    pub fn ident(&'a self) -> Result<BTreeMap<u32, Ident>> {
        let top = self.top()?;

        extract_table(
            self.0,
            &self.1,
            self.0.oid_by_name_under(&top, "rPDU2IdentTableSize")?,
            self.0
                .oid_by_name_under(&top, "rPDU2IdentTable.rPDU2IdentEntry")?,
            "rPDU2Ident",
        )
    }

    pub fn bank_config(&'a self) -> Result<BTreeMap<u32, BankConfiguration>> {
        let top = self.top()?;

        extract_table(
            self.0,
            &self.1,
            self.0.oid_by_name_under(&top, "rPDU2BankTableSize")?,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Bank.rPDU2BankConfigTable.rPDU2BankConfigEntry",
            )?,
            "rPDU2BankConfig",
        )
    }

    pub fn bank_props(&'a self) -> Result<BTreeMap<u32, BankProperties>> {
        let top = self.top()?;

        extract_table(
            self.0,
            &self.1,
            self.0.oid_by_name_under(&top, "rPDU2BankTableSize")?,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Bank.rPDU2BankPropertiesTable.rPDU2BankPropertiesEntry",
            )?,
            "rPDU2BankProperties",
        )
    }

    pub fn bank_status(&'a self) -> Result<BTreeMap<u32, BankStatus>> {
        let top = self.top()?;

        extract_table(
            self.0,
            &self.1,
            self.0.oid_by_name_under(&top, "rPDU2BankTableSize")?,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Bank.rPDU2BankStatusTable.rPDU2BankStatusEntry",
            )?,
            "rPDU2BankStatus",
        )
    }

    pub fn outlet_control(&'a self) -> Result<BTreeMap<u32, OutletControl>> {
        let top = self.top()?;

        extract_table(
            self.0,
            &self.1,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Outlet.rPDU2OutletSwitchedTableSize",
            )?,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Outlet.\
                    rPDU2OutletSwitched.\
                    rPDU2OutletSwitchedControlTable.\
                    rPDU2OutletSwitchedControlEntry",
            )?,
            "rPDU2OutletSwitchedControl",
        )
    }

    pub fn outlet_config(&'a self) -> Result<BTreeMap<u32, OutletConfig>> {
        let top = self.top()?;

        extract_table(
            self.0,
            &self.1,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Outlet.rPDU2OutletSwitchedTableSize",
            )?,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Outlet.\
                    rPDU2OutletSwitched.\
                    rPDU2OutletSwitchedConfigTable.\
                    rPDU2OutletSwitchedConfigEntry",
            )?,
            "rPDU2OutletSwitchedConfig",
        )
    }

    pub fn outlet_props(&'a self) -> Result<BTreeMap<u32, OutletProperties>> {
        let top = self.top()?;

        extract_table(
            self.0,
            &self.1,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Outlet.rPDU2OutletSwitchedTableSize",
            )?,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Outlet.\
                    rPDU2OutletSwitched.\
                    rPDU2OutletSwitchedPropertiesTable.\
                    rPDU2OutletSwitchedPropertiesEntry",
            )?,
            "rPDU2OutletSwitchedProperties",
        )
    }

    pub fn outlet_status(&'a self) -> Result<BTreeMap<u32, OutletStatus>> {
        let top = self.top()?;

        extract_table(
            self.0,
            &self.1,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Outlet.rPDU2OutletSwitchedTableSize",
            )?,
            self.0.oid_by_name_under(
                &top,
                "rPDU2Outlet.\
                    rPDU2OutletSwitched.\
                    rPDU2OutletSwitchedStatusTable.\
                    rPDU2OutletSwitchedStatusEntry",
            )?,
            "rPDU2OutletSwitchedStatus",
        )
    }

}

#[tokio::main]
async fn main() -> Result<()> {
    let a = getopts::Options::new()
        .optflag("v", "", "verbose output")
        .parsing_style(getopts::ParsingStyle::StopAtFirstFree)
        .parse(std::env::args().skip(1))?;

    if a.free.len() != 1 {
        bail!("IP address of SNMP target?");
    }

    let _verbose = a.opt_present("v");

    let addr: std::net::IpAddr = a.free[0].parse()?;
    println!("using target address {addr}");

    let bind = match &addr {
        std::net::IpAddr::V4(_) => "0.0.0.0:0",
        std::net::IpAddr::V6(_) => "[::]:0",
    };

    let tree = populate_mib()?;

    let base = "internet.private.enterprises.apc.products.hardware.rPDU2";
    let top = tree.oid_by_name(base)?;
    let name = tree.oid_name(&top)?;

    println!("top oid = {name} -> {top}");

    println!("creating client...");
    let c = csnmp::Snmp2cClient::new(
        std::net::SocketAddr::new(addr, 161),
        b"muppets".to_vec(),
        Some(bind.parse()?),
        Some(Duration::from_secs(5)),
        0,
    )
    .await?;

    println!("walking from {name} ({top}) ...");

    let res = RPdu2(&tree, c.walk_bulk(top, 63).await?);

    let outlet_status = res.outlet_status()?;
    println!("outlet_status = {outlet_status:#?}");

    let outlet_props = res.outlet_props()?;
    println!("outlet_props = {outlet_props:#?}");

    let outlet_config = res.outlet_config()?;
    println!("outlet_config = {outlet_config:#?}");

    let outlet_control = res.outlet_control()?;
    println!("outlet_control = {outlet_control:#?}");

    let ident = res.ident()?;
    println!("ident = {ident:#?}");

    let bank_status = res.bank_status()?;
    println!("bank_status = {bank_status:#?}");

    let bank_props = res.bank_props()?;
    println!("bank_props = {bank_props:#?}");

    let bank_config = res.bank_config()?;
    println!("bank_config = {bank_config:#?}");

    Ok(())
}
