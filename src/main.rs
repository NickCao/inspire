use tokio::net::UnixListener;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::server::UdsConnectInfo;
use tonic::{transport::Server, Request, Response, Status};
use workloadapi::spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer};
use workloadapi::*;

pub mod workloadapi {
    tonic::include_proto!("_");
}

pub struct Inspire {
    pub ca: rcgen::Certificate,
}

impl Default for Inspire {
    fn default() -> Self {
        let mut params = rcgen::CertificateParams::default();
        params.alg = &rcgen::PKCS_ED25519;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let ca = rcgen::Certificate::from_params(params).unwrap();
        Self { ca }
    }
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
        let conn_info = request
            .extensions()
            .get::<UdsConnectInfo>()
            .ok_or(Status::aborted("failed to get coonnection info"))?;
        let cred = conn_info
            .peer_cred
            .ok_or(Status::aborted("failed to get peer cred"))?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let proc = procfs::process::Process::new(cred.pid().unwrap()).unwrap();
        let cgroups = proc.cgroups().unwrap();
        let ca_der = self.ca.serialize_der().unwrap();
        let mut svids = vec![];
        for cgroup in cgroups {
            let trust_domain = url::Url::parse("spiffe://localhost").unwrap();
            let spiffe_id: String = trust_domain.join(&cgroup.pathname).unwrap().into();
            let mut params = rcgen::CertificateParams::default();
            params.alg = &rcgen::PKCS_ED25519;
            params
                .subject_alt_names
                .push(rcgen::SanType::URI(spiffe_id.clone()));
            let cert = rcgen::Certificate::from_params(params).unwrap();
            let der = cert.serialize_der_with_signer(&self.ca).unwrap();
            svids.push(X509svid {
                spiffe_id: spiffe_id.clone(),
                x509_svid: der.clone(),
                x509_svid_key: cert.serialize_private_key_der(),
                bundle: ca_der.clone(),
                hint: "local".to_string(),
            });
        }
        tokio::spawn(async move {
            loop {
                if let Err(_) = tx
                    .send(Ok(X509svidResponse {
                        crl: vec![],
                        federated_bundles: std::collections::HashMap::new(),
                        svids: svids.clone(),
                    }))
                    .await
                {
                    return;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
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
    let uds = UnixListener::bind("inspire")?;
    let uds_stream = UnixListenerStream::new(uds);
    let inspire = Inspire::default();
    Server::builder()
        .add_service(SpiffeWorkloadApiServer::new(inspire))
        .serve_with_incoming(uds_stream)
        .await?;
    Ok(())
}
