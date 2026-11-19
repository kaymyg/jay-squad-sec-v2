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

