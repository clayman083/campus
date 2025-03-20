use tonic;
use tonic::transport::Server;
use tonic_reflection;
use tower::ServiceBuilder;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid;

use passport::auth_server::{Auth, AuthServer};
use passport::{RegisterRequest, RegisterResponse, User};

pub mod metrics;
use crate::metrics::{MetricsMiddlewareLayer, start_metrics_server};

pub mod proto {
    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("passport_descriptor");
}

pub mod passport {
    tonic::include_proto!("passport");
}

#[derive(Debug)]
pub struct AuthService {}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn register(
        &self,
        request: tonic::Request<RegisterRequest>,
    ) -> Result<tonic::Response<RegisterResponse>, tonic::Status> {
        let user_id = uuid::Uuid::new_v4();
        let user = User {
            id: user_id.to_string(),
            username: request.into_inner().username,
        };

        let response = RegisterResponse { user: Some(user) };

        Ok(tonic::Response::new(response))
    }
}

async fn start_grpc_server(addr: String, debug: bool) {
    tracing::info!("gRPC server is listening on {}", addr);

    let auth_service = AuthService {};
    let svc = AuthServer::new(auth_service);

    let layer = ServiceBuilder::new()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(MetricsMiddlewareLayer {})
        .into_inner();

    let mut server = Server::builder().layer(layer).add_service(svc);

    if debug {
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
            .build_v1()
            .unwrap();

        server = server.add_service(reflection_service);
        tracing::info!("gRPC reflection service is enabled");
    }

    server.serve(addr.parse().unwrap()).await.unwrap();
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=trace", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false).json())
        .init();

    let debug: String = std::env::var("DEBUG").unwrap_or_else(|_| "0".to_string());

    let (_grpc_server, _metrics_server) = tokio::join!(
        start_grpc_server("0.0.0.0:5000".to_owned(), debug.to_lowercase() == "1"),
        start_metrics_server("0.0.0.0:3000".to_owned())
    );
}
