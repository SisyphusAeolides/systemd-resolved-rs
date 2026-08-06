// SPDX-License-Identifier: LGPL-2.1-or-later
fn add_record_value(database: &mut HashMap<String, Vec<StaticRecord>>, value: &Value) {
    let Some((owner, resource)) = parse_record_value(value) else {
        return;
    };
    let rrset = database.entry(owner).or_default();
    if !rrset.contains(&resource) {
        rrset.push(resource);
    }
}

fn parse_record_value(value: &Value) -> Option<(String, StaticRecord)> {
    let key = value.get("key")?;
    let owner = key.get("name")?.as_str()?;
    wire::encode_name(owner).ok()?;
    let rr_type = u16::try_from(key.get("type")?.as_u64()?).ok()?;
    let class = match key.get("class") {
        Some(value) => u16::try_from(value.as_u64()?).ok()?,
        None => CLASS_IN,
    };

    let rdata = match rr_type {
        TYPE_A => match parse_ip_address(value.get("address")?)? {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(_) => return None,
        },
        TYPE_AAAA => match parse_ip_address(value.get("address")?)? {
            IpAddr::V4(_) => return None,
            IpAddr::V6(address) => address.octets().to_vec(),
        },
        TYPE_PTR | TYPE_NS | TYPE_CNAME | TYPE_DNAME => {
            let target = value.get("name")?.as_str()?;
            wire::encode_name(target).ok()?
        }
        _ => return None,
    };

    Some((
        canonical_name(owner),
        StaticRecord {
            class,
            rr_type,
            rdata,
        },
    ))
}

fn parse_ip_address(value: &Value) -> Option<IpAddr> {
    if let Some(address) = value.as_str() {
        return address.parse().ok();
    }
    let bytes = value
        .as_array()?
        .iter()
        .map(|value| value.as_u64().and_then(|number| u8::try_from(number).ok()))
        .collect::<Option<Vec<_>>>()?;
    match bytes.as_slice() {
        [a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        bytes if bytes.len() == 16 => {
            let bytes: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

