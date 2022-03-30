use argh::FromArgs;
use openssl::asn1::*;
use openssl::bn::*;
use openssl::error::ErrorStack;
use openssl::hash::*;
use openssl::pkey::*;
use openssl::x509::extension::*;
use openssl::x509::*;
use tokio::net::UnixListener;
use tokio::sync::watch::*;
use tokio::time::*;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::server::UdsConnectInfo;
use tonic::{transport::Server, Request, Response, Status};
use workloadapi::spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer};
use workloadapi::*;

pub mod workloadapi {
    tonic::include_proto!("_");
}

#[derive(FromArgs, Clone)]
/// A partial implementation of the SPIFFE Workload API
struct Args {
    /// path to listen on (default: /tmp/inspire)
    #[argh(option, short = 'l', default = "String::from(\"/tmp/inspire\")")]
    listen: String,
}

struct Inspire {
    watch: Receiver<(X509, PKey<Private>)>,
}

impl Inspire {
    fn new() -> Self {
        let (tx, watch) = channel(ca().unwrap());
        tokio::spawn(async move {
            loop {
                tx.send_replace(ca().unwrap());
                sleep(Duration::from_millis(10000000)).await;
            }
        });
        Self { watch }
    }
}

fn ca() -> Result<(X509, PKey<Private>), ErrorStack> {
    let pkey = PKey::generate_ed25519()?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let mut name = X509Name::builder()?;
    name.append_entry_by_text("O", "SPIFFE")?;
    name.append_entry_by_text("CN", "ca")?;
    let name = name.build();
    builder.set_issuer_name(&name)?;
    builder.set_subject_name(&name)?;
    let mut bn = BigNum::new()?;
    bn.rand(127, MsbOption::MAYBE_ZERO, false)?;
    // TODO: proper expiration time
    builder.set_serial_number(Asn1Integer::from_bn(&bn)?.as_ref())?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
    builder.set_pubkey(&pkey)?;
    let mut san = SubjectAlternativeName::new();
    san.critical();
    san.uri("spiffe://localhost");
    let san = san.build(&builder.x509v3_context(None, None))?;
    builder.append_extension(san)?;
    let mut usage = KeyUsage::new();
    usage.critical();
    usage.key_cert_sign();
    usage.crl_sign();
    let usage = usage.build()?;
    builder.append_extension(usage)?;
    let mut basic = BasicConstraints::new();
    basic.critical();
    basic.ca();
    let basic = basic.build()?;
    builder.append_extension(basic)?;
    let identifier = SubjectKeyIdentifier::new();
    let identifier = identifier.build(&builder.x509v3_context(None, None))?;
    builder.append_extension(identifier)?;
    builder.sign(&pkey, MessageDigest::null())?;
    let ca = builder.build();
    Ok((ca, pkey))
}

fn issue(spiffe_id: &str, ca_cert: &X509, ca_pkey: &PKey<Private>) -> Result<X509svid, ErrorStack> {
    let pkey = PKey::generate_ed25519()?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let mut name = X509Name::builder()?;
    name.append_entry_by_text("O", "SPIFFE")?;
    name.append_entry_by_text("CN", "workload")?;
    let name = name.build();
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_subject_name(&name)?;
    let mut bn = BigNum::new()?;
    bn.rand(127, MsbOption::MAYBE_ZERO, false)?;
    // TODO: proper expiration time
    builder.set_serial_number(Asn1Integer::from_bn(&bn)?.as_ref())?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
    builder.set_pubkey(&pkey)?;
    let mut san = SubjectAlternativeName::new();
    san.critical();
    san.uri(spiffe_id);
    let san = san.build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(san)?;
    let mut usage = KeyUsage::new();
    usage.critical();
    usage.digital_signature();
    let usage = usage.build()?;
    builder.append_extension(usage)?;
    let mut ext_usage = ExtendedKeyUsage::new();
    ext_usage.critical();
    ext_usage.server_auth();
    ext_usage.client_auth();
    let ext_usage = ext_usage.build()?;
    builder.append_extension(ext_usage)?;
    let mut basic = BasicConstraints::new();
    basic.critical();
    let basic = basic.build()?;
    builder.append_extension(basic)?;
    let identifier = SubjectKeyIdentifier::new();
    let identifier = identifier.build(&builder.x509v3_context(None, None))?;
    builder.append_extension(identifier)?;
    let mut auth_identifier = AuthorityKeyIdentifier::new();
    auth_identifier.keyid(true);
    let auth_identifier = auth_identifier.build(&builder.x509v3_context(Some(ca_cert), None))?;
    builder.append_extension(auth_identifier)?;
    builder.sign(ca_pkey, MessageDigest::null())?;
    let cert = builder.build();
    Ok(X509svid {
        spiffe_id: spiffe_id.to_owned(),
        x509_svid: cert.to_der()?,
        x509_svid_key: pkey.private_key_to_der()?,
        bundle: ca_cert.to_der()?,
        hint: "local".to_owned(),
    })
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for Inspire {
    type FetchX509SVIDStream = ReceiverStream<Result<X509svidResponse, Status>>;
    type FetchX509BundlesStream = ReceiverStream<Result<X509BundlesResponse, Status>>;
    type FetchJWTBundlesStream = ReceiverStream<Result<JwtBundlesResponse, Status>>;
    async fn fetch_x509svid(
        &self,
        request: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        let pid = request
            .extensions()
            .get::<UdsConnectInfo>()
            .ok_or(Status::aborted("failed to get conn info"))?
            .peer_cred
            .ok_or(Status::aborted("failed to get peer cred"))?
            .pid()
            .ok_or(Status::aborted("failed to get pid"))?;
        let cgroups = procfs::process::Process::new(pid)
            .or(Err(Status::aborted("failed to lookup process")))?
            .cgroups()
            .or(Err(Status::aborted("failed to lookup cgroups")))?;

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut watch = self.watch.clone();
        tokio::spawn(async move {
            while watch.changed().await.is_ok() {
                let mut svids = vec![];
                for cgroup in &cgroups {
                    // TODO: rework handling of path
                    let spiffe_id: String = url::Url::parse("spiffe://localhost/cgroup/")
                        .unwrap()
                        .join(cgroup.pathname.strip_prefix("/").unwrap())
                        .unwrap()
                        .into();
                    let svid = issue(&spiffe_id, &watch.borrow().0, &watch.borrow().1).unwrap();
                    svids.push(svid);
                }
                if tx
                    .send(Ok(X509svidResponse {
                        crl: vec![],
                        federated_bundles: std::collections::HashMap::new(),
                        svids,
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
    async fn fetch_x509_bundles(
        &self,
        _: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        Err(Status::unimplemented("wip"))
    }
    async fn fetch_jwtsvid(
        &self,
        _: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        Err(Status::unimplemented("unimplemented"))
    }
    async fn fetch_jwt_bundles(
        &self,
        _: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        Err(Status::unimplemented("unimplemented"))
    }
    async fn validate_jwtsvid(
        &self,
        _: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        Err(Status::unimplemented("unimplemented"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = argh::from_env();
    drop(std::fs::remove_file(&args.listen));
    let uds = UnixListener::bind(&args.listen)?;
    let uds_stream = UnixListenerStream::new(uds);
    let inspire = Inspire::new();
    Server::builder()
        .add_service(SpiffeWorkloadApiServer::new(inspire))
        .serve_with_incoming(uds_stream)
        .await?;
    Ok(())
}
