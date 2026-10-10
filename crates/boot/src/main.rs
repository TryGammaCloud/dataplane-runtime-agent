use gammacloud_protocol::GuestState;

fn main() {
    // Development VM bootstrap only. No SEV-SNP evidence is collected here.
    println!("gammacloud-boot state={} attestation=unverified confidential=false", GuestState::Starting.as_str());
    println!("gammacloud-boot state={} attestation=unverified confidential=false", GuestState::Ready.as_str());
}
