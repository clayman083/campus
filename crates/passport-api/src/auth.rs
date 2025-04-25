use tonic;
use tonic::service::Interceptor;
use tonic_types::{ErrorDetails, StatusExt};

#[derive(Clone, Copy)]
pub struct AuthInterceptor {}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, request: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        let path = request.extensions().get::<String>();

        // Проверяем, если метод соответствует исключаемым роутам
        if let Some(path) = path {
            // Исключения для роутов
            if path == "/passport.Auth/Register" {
                return Ok(request); // Пропускаем проверку аутентификации
            }
        }

        let token: tonic::metadata::MetadataValue<_> = "Bearer some-secret-token".parse().unwrap();

        match request.metadata().get("authorization") {
            Some(t) if token == t => Ok(request),
            _ => {
                let mut err_details = ErrorDetails::new();

                err_details.add_bad_request_violation("foo", "bar");

                Err(tonic::Status::with_error_details(
                    tonic::Code::Unauthenticated,
                    "No valid auth token",
                    err_details,
                ))
            }
        }
    }
}
