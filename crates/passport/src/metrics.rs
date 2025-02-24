use axum::{Router, extract::MatchedPath, routing::get};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::{future::ready, time::Instant};
use std::{
    ops::Not,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceBuilder};
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

#[derive(Debug, Clone, Default)]
pub struct MetricsMiddlewareLayer {}

impl<S> Layer<S> for MetricsMiddlewareLayer {
    type Service = MetricsMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        MetricsMiddleware { inner: service }
    }
}

#[derive(Debug, Clone)]
pub struct MetricsMiddleware<S> {
    inner: S,
}

type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for MetricsMiddleware<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let start = Instant::now();
            let path = if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
                matched_path.as_str().to_owned()
            } else {
                req.uri().path().to_owned()
            };

            // Do extra async work here...
            let response = inner.call(req).await?;

            if path.contains("grpc.reflection.v1.ServerReflection").not() {
                let labels = [("method", path)];

                metrics::counter!("grpc_requests_total", &labels).increment(1);
                metrics::histogram!("grpc_requests_duration_seconds", &labels)
                    .record(start.elapsed().as_secs_f64());
            }

            Ok(response)
        })
    }
}

fn setup_metrics_recorder() -> PrometheusHandle {
    const EXPONENTIAL_SECONDS: &[f64] = &[
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("http_requests_duration_seconds".to_string()),
            EXPONENTIAL_SECONDS,
        )
        .unwrap()
        .install_recorder()
        .unwrap()
}

fn metrics_app() -> Router {
    let recoder_handler = setup_metrics_recorder();
    Router::new()
        .route("/metrics", get(move || ready(recoder_handler.render())))
        .route_layer(
            ServiceBuilder::new().layer(
                TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::DEBUG))
                    .on_response(trace::DefaultOnResponse::new().level(Level::DEBUG)),
            ),
        )
}

pub async fn start_metrics_server(addr: String) {
    let app = metrics_app();

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    tracing::info!(
        "Metrics server is listening on {}",
        listener.local_addr().unwrap()
    );
    axum::serve(listener, app).await.unwrap();
}
