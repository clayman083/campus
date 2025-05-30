use tonic;
use tonic::service::InterceptorLayer;
use tonic::transport::Server;
use tonic_reflection;
use tower::ServiceBuilder;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid;

use protocols::passport;
use protocols::passport::auth_server::{Auth, AuthServer};

mod auth;
use crate::auth::AuthInterceptor;

pub mod metrics;
use crate::metrics::{MetricsMiddlewareLayer, start_metrics_server};

#[derive(Debug)]
pub struct AuthService {}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn register(
        &self,
        request: tonic::Request<passport::RegisterRequest>,
    ) -> Result<tonic::Response<passport::RegisterResponse>, tonic::Status> {
        let user_id = uuid::Uuid::new_v4();
        let user = passport::User {
            id: user_id.to_string(),
            username: request.into_inner().username,
        };

        let response = passport::RegisterResponse { user: Some(user) };

        Ok(tonic::Response::new(response))
    }

    async fn login(
        &self,
        _: tonic::Request<passport::LoginRequest>,
    ) -> Result<tonic::Response<passport::TokenResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not implemented"))
    }

    async fn refresh(
        &self,
        _: tonic::Request<passport::Empty>,
    ) -> Result<tonic::Response<passport::TokenResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not implemented"))
    }

    async fn get_profile(
        &self,
        _: tonic::Request<passport::Empty>,
    ) -> Result<tonic::Response<passport::User>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not implemented"))
    }
}

async fn start_grpc_server(addr: String, debug: bool) {
    tracing::info!("gRPC server is listening on {}", addr);

    let auth_service = AuthService {};
    let auth_interceptor = AuthInterceptor {};
    let svc = AuthServer::new(auth_service);

    let layer = ServiceBuilder::new()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(MetricsMiddlewareLayer {})
        .into_inner();

    let mut server = Server::builder()
        .layer(layer)
        .layer(InterceptorLayer::new(auth_interceptor))
        .add_service(svc);

    if debug {
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(protocols::passport_proto::FILE_DESCRIPTOR_SET)
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
