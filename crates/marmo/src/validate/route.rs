//! Route and rule validation.

use super::*;

pub(super) fn validate_route(
    route: &Route, outbounds: &[RawOutbound], inbounds: &[RawInbound],
) -> Result<(), ConfigError> {
    if !is_valid_route_target(&route.final_outbound, outbounds) {
        return Err(fail(
            "route.final",
            format!("unknown outbound '{}'", route.final_outbound),
        ));
    }
    for (index, rule) in route.rules.iter().enumerate() {
        if !is_valid_route_target(&rule.outbound, outbounds) {
            return Err(fail(
                format!("route.rules[{index}].outbound"),
                format!("unknown '{}'", rule.outbound),
            ));
        }
        validate_rule(rule, index, inbounds)?;
    }
    Ok(())
}

pub(super) fn validate_rule(
    rule: &Rule, index: usize, inbounds: &[RawInbound],
) -> Result<(), ConfigError> {
    if let Some(domains) = rule.domain.as_deref() {
        for domain in domains {
            if domain.is_empty() {
                return Err(fail(format!("route.rules[{index}].domain"), "empty value"));
            }
        }
    }
    if let Some(suffixes) = rule.domain_suffix.as_deref() {
        for suffix in suffixes {
            if suffix.is_empty() {
                return Err(fail(
                    format!("route.rules[{index}].domain_suffix"),
                    "empty value",
                ));
            }
        }
    }
    validate_rule_values(
        rule.domain_keyword.as_deref(),
        &format!("route.rules[{index}].domain_keyword"),
        Some(128),
    )?;
    validate_rule_values(
        rule.domain_set.as_deref(),
        &format!("route.rules[{index}].domain_set"),
        Some(128),
    )?;
    validate_rule_values(
        rule.geoip.as_deref(),
        &format!("route.rules[{index}].geoip"),
        Some(128),
    )?;
    if let Some(cidrs) = rule.ip_cidr.as_deref() {
        for cidr in cidrs {
            if Cidr::parse(cidr).is_err() {
                return Err(fail(
                    format!("route.rules[{index}].ip_cidr"),
                    format!("invalid '{cidr}'"),
                ));
            }
        }
    }
    if let Some(ports) = rule.port.as_deref()
        && ports.is_empty()
    {
        return Err(fail(
            format!("route.rules[{index}].port"),
            "must not be empty",
        ));
    }
    validate_port_ranges(rule.port_range.as_deref(), index)?;
    validate_rule_inbounds(rule.inbound.as_deref(), index, inbounds)?;
    validate_rule_values(
        rule.process_name.as_deref(),
        &format!("route.rules[{index}].process_name"),
        Some(255),
    )?;
    validate_rule_values(
        rule.process_path.as_deref(),
        &format!("route.rules[{index}].process_path"),
        Some(4096),
    )?;
    Ok(())
}

pub(super) fn validate_rule_values(
    values: Option<&[String]>, path: &str, max_len: Option<usize>,
) -> Result<(), ConfigError> {
    let Some(values) = values else {
        return Ok(());
    };
    if values.is_empty() {
        return Err(fail(path, "must not be empty"));
    }
    for (index, value) in values.iter().enumerate() {
        if value.is_empty() {
            return Err(fail(format!("{path}[{index}]"), "empty value"));
        }
        if value.contains('\0') {
            return Err(fail(format!("{path}[{index}]"), "must not contain NUL"));
        }
        if let Some(max_len) = max_len
            && value.len() > max_len
        {
            return Err(fail(
                format!("{path}[{index}]"),
                format!("must be at most {max_len} bytes"),
            ));
        }
        if values[..index].contains(value) {
            return Err(fail(format!("{path}[{index}]"), "duplicate value"));
        }
    }
    Ok(())
}

pub(super) fn validate_port_ranges(
    ranges: Option<&[[u16; 2]]>, rule_index: usize,
) -> Result<(), ConfigError> {
    let Some(ranges) = ranges else {
        return Ok(());
    };
    if ranges.is_empty() {
        return Err(fail(
            format!("route.rules[{rule_index}].port_range"),
            "must not be empty",
        ));
    }
    for (index, &[start, end]) in ranges.iter().enumerate() {
        let path = format!("route.rules[{rule_index}].port_range[{index}]");
        if start > end {
            return Err(fail(path, "start must not exceed end"));
        }
        if ranges[..index].contains(&[start, end]) {
            return Err(fail(path, "duplicate range"));
        }
    }
    Ok(())
}

pub(super) fn validate_rule_inbounds(
    tags: Option<&[String]>, rule_index: usize, inbounds: &[RawInbound],
) -> Result<(), ConfigError> {
    let Some(tags) = tags else {
        return Ok(());
    };
    validate_rule_values(
        Some(tags),
        &format!("route.rules[{rule_index}].inbound"),
        None,
    )?;
    for (index, tag) in tags.iter().enumerate() {
        if !inbounds.iter().any(|inbound| inbound.tag == *tag) {
            return Err(fail(
                format!("route.rules[{rule_index}].inbound[{index}]"),
                format!("unknown inbound '{tag}'"),
            ));
        }
    }
    Ok(())
}

pub(super) fn is_valid_route_target(tag: &str, outbounds: &[RawOutbound]) -> bool {
    tag == "direct" || tag == "reject" || outbounds.iter().any(|item| item.tag == tag)
}
