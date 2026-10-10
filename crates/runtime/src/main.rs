use gammacloud_protocol::GuestState;

fn main() {
    // Deliberately no remote listener or arbitrary command execution in this skeleton.
    println!("gammacloud-runtime state={} attestation=unverified confidential=false", GuestState::Ready.as_str());
}
