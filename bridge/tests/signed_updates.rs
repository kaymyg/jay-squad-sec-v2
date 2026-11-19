use jay_squad_sec_bridge::{
    apply_signed_rules, engine_free, engine_new, load_signed_rules, ERR_UPDATE_NOT_CONFIGURED,
};

#[test]
fn rules_load_fails_closed_when_builder_key_is_not_embedded() {
    if option_env!("JSS_ANDROID_BUILDER_PUBLIC_KEY_HEX").is_some() {
        return;
    }
    let handle = engine_new(17);
    assert_ne!(handle, 0);
    let result = load_signed_rules(handle, b"/private/app/files/jss");
    assert_eq!(result, Err(ERR_UPDATE_NOT_CONFIGURED));
    assert_eq!(engine_free(handle), 0);
}

#[test]
fn rules_apply_fails_closed_when_builder_key_is_not_embedded() {
    if option_env!("JSS_ANDROID_BUILDER_PUBLIC_KEY_HEX").is_some() {
        return;
    }
    let handle = engine_new(17);
    assert_ne!(handle, 0);
    let result = apply_signed_rules(handle, b"/private/app/files/jss", b"not-a-patch");
    assert_eq!(result, Err(ERR_UPDATE_NOT_CONFIGURED));
    assert_eq!(engine_free(handle), 0);
}

#[test]
fn a_key_without_an_explicit_min_version_fails_closed() {
    // Only meaningful in a build that embeds a key but omits the minimum
    // version; production builds must set it deliberately (even to 0).
    if option_env!("JSS_ANDROID_BUILDER_PUBLIC_KEY_HEX").is_none()
        || option_env!("JSS_ANDROID_MIN_RULES_VERSION").is_some()
    {
        return;
    }
    let handle = engine_new(17);
    assert_eq!(
        load_signed_rules(handle, b"/private/app/files/jss"),
        Err(ERR_UPDATE_NOT_CONFIGURED)
    );
    assert_eq!(engine_free(handle), 0);
}

#[test]
fn a_malformed_embedded_key_fails_closed() {
    // Runs only in a build whose key is present but not 64 hex characters.
    let Some(key) = option_env!("JSS_ANDROID_BUILDER_PUBLIC_KEY_HEX") else {
        return;
    };
    if key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return;
    }
    let handle = engine_new(18);
    assert_eq!(
        load_signed_rules(handle, b"/private/app/files/jss"),
        Err(ERR_UPDATE_NOT_CONFIGURED)
    );
    assert_eq!(
        apply_signed_rules(handle, b"/private/app/files/jss", b"x"),
        Err(ERR_UPDATE_NOT_CONFIGURED)
    );
    assert_eq!(engine_free(handle), 0);
}
