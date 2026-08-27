use catomicals_node_client::{NodeIdentity, NodeIdentityError, validate_node_identity};

#[test]
fn accepts_inquisition_on_signet_with_active_cat() {
    let identity = NodeIdentity {
        chain: "signet".to_owned(),
        subversion: "/Satoshi:29.4.0/".to_owned(),
        cat_active: true,
    };

    assert_eq!(validate_node_identity(&identity), Ok(()));
}

#[test]
fn rejects_a_node_on_the_wrong_chain() {
    let identity = NodeIdentity {
        chain: "main".to_owned(),
        subversion: "/Satoshi:29.4.0/".to_owned(),
        cat_active: true,
    };

    assert_eq!(
        validate_node_identity(&identity),
        Err(NodeIdentityError::WrongChain("main".to_owned()))
    );
}

#[test]
fn rejects_signet_before_cat_activation() {
    let identity = NodeIdentity {
        chain: "signet".to_owned(),
        subversion: "/Satoshi:29.4.0/".to_owned(),
        cat_active: false,
    };

    assert_eq!(
        validate_node_identity(&identity),
        Err(NodeIdentityError::CatInactive)
    );
}
