pub(crate) fn peer_uid_authorized(owner_uid: u32, peer_uid: u32) -> bool {
    owner_uid == peer_uid
}

#[cfg(test)]
mod tests {
    #[test]
    fn socket_peer_must_match_its_owner() {
        assert!(crate::vsock::peer::peer_uid_authorized(501, 501));
        assert!(!crate::vsock::peer::peer_uid_authorized(501, 502));
    }
}
