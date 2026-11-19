//! Property: under ANY valid rules config, a full attack chain delivered in
//! quick succession must still reach Block. This is the "retune, never
//! disable" guarantee checked end to end through the engine, across defaults
//! and the most lenient configs validation still accepts.

use jay_squad_sec::engine::Engine;
use jay_squad_sec::event::{Event, EventKind::*};
use jay_squad_sec::risk::PolicyAction;
use jay_squad_sec::rules::{kind_index, RulesConfig, DEFAULT_RULES, MAX_HALF_LIFE_MS, MIN_HALF_LIFE_MS};

fn chain_action(rules: RulesConfig) -> PolicyAction {
    let mut e = Engine::new(42);
    e.set_rules(rules).expect("config under test must be valid");
    // Signed binary, so good evidence is working AGAINST detection here.
    let id = e.spawn("victim", b"victim-image", true, None, 0);
    e.tick(0);
    let chain = [UnsignedModuleLoad, RwxAlloc, PrivilegeEscalation, RemoteThreadInjection,
                 CredentialAccess, PersistenceWrite, TempExecution, DeletedExecutable, UnsignedBinary];
    for (i, k) in chain.iter().enumerate() {
        let t = 1_000 + 200 * i as u64; // whole chain within ~2 s
        e.bus.publish(Event { rtid: id, kind: *k, at_ms: t, detail: String::new() });
        e.tick(t);
    }
    let action = e.processes().find(|p| p.rtid == id).unwrap().action;
    action
}

fn lenient_variants() -> Vec<RulesConfig> {
    let mut v = vec![DEFAULT_RULES];
    // Block threshold raised to the maximum the defaults can still reach.
    let mut r = DEFAULT_RULES;
    r.block_at = 150.0; r.suspend_at = 120.0; r.restrict_at = 80.0; r.monitor_at = 40.0;
    v.push(r);
    // Good evidence at its most negative, shortest and longest half-life.
    for hl in [MIN_HALF_LIFE_MS, MAX_HALF_LIFE_MS] {
        let mut r = DEFAULT_RULES;
        r.weights[kind_index(SignedBinary)] = -20.0;
        r.weights[kind_index(StableTick)] = -20.0;
        r.half_life_ms = hl;
        v.push(r);
    }
    // Indicators lowered as far as reachability allows for a modest block_at.
    let mut r = DEFAULT_RULES;
    for k in [UnsignedBinary, UnsignedModuleLoad, RwxAlloc, RemoteThreadInjection, CredentialAccess,
              PersistenceWrite, PrivilegeEscalation, TempExecution, DeletedExecutable] {
        r.weights[kind_index(k)] = 8.0;
    }
    r.monitor_at = 5.0; r.restrict_at = 15.0; r.suspend_at = 25.0; r.block_at = 40.0; // 5 x 8 = 40
    v.push(r);
    v
}

#[test]
fn attack_chain_reaches_block_under_every_valid_config() {
    for (i, rules) in lenient_variants().into_iter().enumerate() {
        assert_eq!(rules.validate(), Ok(()), "variant {i} must be valid");
        assert_eq!(chain_action(rules), PolicyAction::Block, "variant {i} let the chain through");
    }
}
