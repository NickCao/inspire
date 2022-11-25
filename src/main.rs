use argh::FromArgs;
use openssl::asn1::*;
use openssl::bn::*;
use openssl::hash::*;
use openssl::pkey::*;
use openssl::x509::extension::*;
use openssl::x509::*;
use std::time::*;
use tokio::net::UnixListener;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::server::UdsConnectInfo;
use tonic::{transport::Server, Request, Response, Status};
use workloadapi::spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer};
use workloadapi::*;

const ROTATION_INTERVAL: u64 = 3600;

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
    ca: (X509, PKey<Private>),
}

impl Inspire {
    fn new() -> anyhow::Result<Self> {
        Ok(Self { ca: ca()? })
    }
}

fn ca() -> anyhow::Result<(X509, PKey<Private>)> {
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
    builder.set_serial_number(Asn1Integer::from_bn(&bn)?.as_ref())?;
    // see https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
    builder.set_not_after(Asn1Time::from_str_x509("99991231235959Z")?.as_ref())?;
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

fn issue(spiffe_id: &str, bundle: &(X509, PKey<Private>)) -> anyhow::Result<X509svid> {
    let (ca_cert, ca_pkey) = &bundle;
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
    builder.set_serial_number(Asn1Integer::from_bn(&bn)?.as_ref())?;
    let not_after = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .checked_add(Duration::from_secs(ROTATION_INTERVAL * 2))
        .ok_or(anyhow::anyhow!("failed to calculate not after"))?
        .as_secs();
    builder.set_not_after(Asn1Time::from_unix(not_after.try_into()?)?.as_ref())?;
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
        bundle: bundle.0.to_der()?,
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
        let trust_base = url::Url::parse("spiffe://localhost/cgroup/")
            .or(Err(Status::aborted("failed to parse trust base")))?;
        let ca = self.ca.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(ROTATION_INTERVAL));
            loop {
                let svids: anyhow::Result<Vec<X509svid>> = (|| {
                    Ok(cgroups
                        .iter()
                        // WARNING: should sanitize cgroup pathname
                        .map(|cgroup| cgroup.pathname.strip_prefix("/"))
                        .collect::<Option<Vec<&str>>>()
                        .ok_or(anyhow::anyhow!("failed to strip prefix from pathname"))?
                        .iter()
                        .map(|pathname| trust_base.join(pathname))
                        .collect::<Result<Vec<url::Url>, _>>()?
                        .iter()
                        .map(|id| issue(id.as_str(), &ca))
                        .collect::<Result<Vec<X509svid>, _>>()?)
                })();
                let resp = match svids {
                    Ok(svids) => Ok(X509svidResponse {
                        crl: vec![],
                        federated_bundles: std::collections::HashMap::new(),
                        svids,
                    }),
                    Err(_) => Err(Status::aborted("failed to issue svids")),
                };
                if tx.send(resp).await.is_err() {
                    return;
                }
                interval.tick().await;
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
    let inspire = Inspire::new()?;
    Server::builder()
        .add_service(SpiffeWorkloadApiServer::new(inspire))
        .serve_with_incoming(uds_stream)
        .await?;
    Ok(())
}
