// SPDX-License-Identifier: LGPL-2.1-or-later
pub fn refused_for(query: &[u8]) -> Result<Vec<u8>, WireError> {
    validate(query, false)?;
    let mut response = query[..question_end(query)?].to_vec();
    let mut flags = read_u16(&response, 2)?;
    flags |= FLAG_QR | FLAG_RA;
    flags &= !(FLAG_AA | FLAG_TC | RCODE_MASK);
    flags |= 5;
    write_u16(&mut response, 2, flags)?;
    response[6..12].fill(0);
    Ok(response)
}
