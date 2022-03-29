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

#[derive(Debug, Default)]
pub struct Inspire {}

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
        println!("{:?}", cred);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            loop {
                tx.send(Ok(X509svidResponse {
                    crl: vec![],
                    federated_bundles: std::collections::HashMap::new(),
                    svids: vec![],
                }))
                .await;
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
